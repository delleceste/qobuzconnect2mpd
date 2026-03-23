/* Copyright (C) 2024 J.F.Dockes
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, write to the
 *  Free Software Foundation, Inc.,
 *  59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "mdns.hxx"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>
#include "qclog.hxx"

namespace QConnect {

// ============================================================
//  DNS packet building utilities
// ============================================================

namespace {

// Append a big-endian uint16 / uint32 to a string buffer
void append16(std::string& b, uint16_t v) {
    b += static_cast<char>((v >> 8) & 0xff);
    b += static_cast<char>( v       & 0xff);
}

void append32(std::string& b, uint32_t v) {
    b += static_cast<char>((v >> 24) & 0xff);
    b += static_cast<char>((v >> 16) & 0xff);
    b += static_cast<char>((v >>  8) & 0xff);
    b += static_cast<char>( v        & 0xff);
}

// Encode a DNS name as a sequence of length-prefixed labels.
// Input "foo.bar.baz." -> \x03foo\x03bar\x03baz\x00
// Each label must fit in 63 bytes.
std::string encodeName(const std::string& name) {
    std::string result;
    std::istringstream ss(name);
    std::string label;
    while (std::getline(ss, label, '.')) {
        if (label.empty()) continue; // trailing dot
        result += static_cast<char>(label.size() & 0x3f);
        result += label;
    }
    result += '\x00';
    return result;
}

// Encode a DNS pointer (offset from start of packet) as 2 bytes
std::string encodePointer(uint16_t offset) {
    std::string r;
    r += static_cast<char>(0xc0 | ((offset >> 8) & 0x3f));
    r += static_cast<char>(offset & 0xff);
    return r;
}

// Build a TXT RDATA containing a list of "key=value" strings.
// Each string is prefixed by its 1-byte length.
std::string buildTxtRdata(const std::vector<std::string>& pairs) {
    std::string r;
    for (const auto& p : pairs) {
        if (p.size() > 255) continue;
        r += static_cast<char>(p.size());
        r += p;
    }
    return r;
}

// Build a single DNS Resource Record.
// name:   already encoded name bytes (labels or pointer)
// type:   RR type (PTR=12, SRV=33, TXT=16, A=1)
// cls:    RR class; IN=1, IN+FLUSH=0x8001
// ttl:    time-to-live in seconds (0 = goodbye)
// rdata:  raw RDATA bytes
std::string buildRR(const std::string& name,
                     uint16_t type,
                     uint16_t cls,
                     uint32_t ttl,
                     const std::string& rdata) {
    std::string r = name;
    append16(r, type);
    append16(r, cls);
    append32(r, ttl);
    append16(r, static_cast<uint16_t>(rdata.size()));
    r += rdata;
    return r;
}

// Resolve the first non-loopback IPv4 address on the given interface
// (or any interface if iface is empty).  Returns "" on failure.
std::string getIfaceAddr(const std::string& iface) {
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) return {};
    std::string result;
    for (struct ifaddrs* ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (!iface.empty() && iface != ifa->ifa_name) continue;
        char buf[INET_ADDRSTRLEN];
        auto* sin = reinterpret_cast<const struct sockaddr_in*>(ifa->ifa_addr);
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) {
            result = buf;
            break;
        }
    }
    freeifaddrs(ifap);
    return result;
}

// mDNS multicast group and port
static constexpr const char* MDNS_GROUP = "224.0.0.251";
static constexpr int         MDNS_PORT  = 5353;

// DNS RR type constants
static constexpr uint16_t TYPE_A   = 1;
static constexpr uint16_t TYPE_PTR = 12;
static constexpr uint16_t TYPE_TXT = 16;
static constexpr uint16_t TYPE_SRV = 33;

// DNS class constants
static constexpr uint16_t CLASS_IN       = 1;
static constexpr uint16_t CLASS_IN_FLUSH = 0x8001; // cache-flush bit set

} // anonymous namespace

// ============================================================
//  MdnsAnnouncer implementation
// ============================================================

MdnsAnnouncer::MdnsAnnouncer(const std::string& uuid,
                               const std::string& name,
                               int                port,
                               const std::string& iface)
    : m_uuid(uuid), m_name(name), m_port(port), m_iface(iface)
{
    // Build the instance name: "<friendly-name>._qobuz-connect._tcp.local."
    // The Qobuz app uses the instance label as the device display name;
    // it must be the human-readable friendly name, not the UUID.
    m_instance = m_name + "._qobuz-connect._tcp.local.";

    // Sanitise the name for use as a local hostname (lowercase, spaces->hyphens)
    std::string host = name;
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    std::replace(host.begin(), host.end(), ' ', '-');
    // Remove characters not valid in a DNS label
    host.erase(std::remove_if(host.begin(), host.end(),
                               [](unsigned char c) {
                                   return !(std::isalnum(c) || c == '-');
                               }), host.end());
    if (host.empty()) host = "upmpdcli";
    m_hostname = host + ".local.";
}

MdnsAnnouncer::~MdnsAnnouncer() { stop(); }

bool MdnsAnnouncer::openSocket() {
    m_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (m_sock < 0) {
        LOGERR("MdnsAnnouncer: socket() failed: " << strerror(errno) << "\n");
        return false;
    }

    int yes = 1;
    if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        LOGERR("MdnsAnnouncer: SO_REUSEADDR failed: " << strerror(errno) << "\n");
    }
#ifdef SO_REUSEPORT
    if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) < 0) {
        LOGDEB("MdnsAnnouncer: SO_REUSEPORT not available\n");
    }
#endif

    // Bind to MDNS_PORT on all interfaces so we receive incoming queries
    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(MDNS_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(m_sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOGERR("MdnsAnnouncer: bind() failed: " << strerror(errno) << "\n");
        close(m_sock);
        m_sock = -1;
        return false;
    }

    // Join the mDNS multicast group
    struct ip_mreq mreq{};
    inet_pton(AF_INET, MDNS_GROUP, &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = INADDR_ANY;
    if (setsockopt(m_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        LOGERR("MdnsAnnouncer: IP_ADD_MEMBERSHIP failed: " << strerror(errno) << "\n");
        // Non-fatal: we can still send announcements
    }

    // Set multicast TTL to 1 (link-local)
    unsigned char ttl = 1;
    setsockopt(m_sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    // Disable loopback of multicast packets sent by us
    unsigned char loop = 0;
    setsockopt(m_sock, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

    return true;
}

bool MdnsAnnouncer::start() {
    if (!openSocket()) return false;
    m_stop    = false;
    m_running = true;
    m_thread  = std::thread(&MdnsAnnouncer::loop, this);
    return true;
}

void MdnsAnnouncer::stop() {
    if (!m_running) return;
    m_stop = true;
    if (m_thread.joinable()) m_thread.join();
    m_running = false;
    if (m_sock >= 0) { close(m_sock); m_sock = -1; }
}

// Build the complete DNS response packet.
// is_answer_to_query: true -> response bit set and query ID echoed.
// goodbye: true -> all TTLs set to 0 (RFC 6762 §11.3).
std::string MdnsAnnouncer::buildResponse(const std::string& ifaddr,
                                          bool is_answer_to_query,
                                          uint16_t query_id,
                                          bool goodbye) const {
    // All name strings use the "fully qualified" dot-separated form.
    const std::string svcType  = "_qobuz-connect._tcp.local.";
    const std::string instance = m_instance;     // uuid + "._qobuz-connect._tcp.local."
    const std::string hostname = m_hostname;

    const uint32_t ttl_ptr = goodbye ? 0 : TTL_PTR;
    const uint32_t ttl_srv = goodbye ? 0 : TTL_SRV;
    const uint32_t ttl_txt = goodbye ? 0 : TTL_TXT;
    const uint32_t ttl_a   = goodbye ? 0 : TTL_A;

    // We build the packet in stages, tracking byte offsets so we can use
    // DNS pointers to avoid repeating names.
    //
    // Packet layout (offsets are from byte 0 of the DNS message):
    //   0   : DNS header (12 bytes)
    //  12   : PTR RR name  = encodeName(svcType)
    //         PTR RR body
    //  Nptr : SRV RR name  = pointer to instance name embedded in PTR RDATA
    //         SRV RR body
    //  ...
    //
    // For simplicity we encode without compression (no pointers) to keep the
    // implementation straightforward.  mDNS packets are small enough.

    // --- Answer section RRs ---

    // 1. PTR: _qobuz-connect._tcp.local. -> <instance>
    std::string ptrRdata = encodeName(instance);
    std::string ptrRR    = buildRR(encodeName(svcType), TYPE_PTR, CLASS_IN,
                                    ttl_ptr, ptrRdata);

    // 2. SRV: <instance> -> <hostname> port <m_port>
    {   // SRV RDATA = priority(2) + weight(2) + port(2) + target
        // No RDATA builder needed – done inline below
    }
    std::string srvRdata;
    append16(srvRdata, 0);                        // priority
    append16(srvRdata, 0);                        // weight
    append16(srvRdata, static_cast<uint16_t>(m_port));
    srvRdata += encodeName(hostname);
    std::string srvRR = buildRR(encodeName(instance), TYPE_SRV, CLASS_IN_FLUSH,
                                 ttl_srv, srvRdata);

    // 3. TXT: <instance> -> key=value pairs
    // Keys/values must match what the Qobuz app expects (verified against qonductor).
    std::vector<std::string> txtPairs = {
        "path=/devices/"  + m_uuid,
        "type=SPEAKER",                    // device type string, not integer
        "Name="           + m_name,        // display name
        "device_uuid="    + m_uuid,        // UUID with hyphens
        "sdk_version=0.9.6",               // must be >= 0.9.5
    };
    std::string txtRR = buildRR(encodeName(instance), TYPE_TXT, CLASS_IN_FLUSH,
                                 ttl_txt, buildTxtRdata(txtPairs));

    // 4. A: <hostname> -> <ip>
    std::string aRdata;
    struct in_addr ia{};
    inet_pton(AF_INET, ifaddr.c_str(), &ia);
    aRdata.append(reinterpret_cast<const char*>(&ia.s_addr), 4);
    std::string aRR = buildRR(encodeName(hostname), TYPE_A, CLASS_IN_FLUSH,
                               ttl_a, aRdata);

    // --- DNS header ---
    // Flags: QR=1 (response), AA=1 (authoritative), no error
    uint16_t flags = is_answer_to_query ? 0x8400u : 0x8400u;
    uint16_t id    = is_answer_to_query ? query_id : 0;

    std::string hdr;
    append16(hdr, id);
    append16(hdr, flags);
    append16(hdr, 0);   // QDCOUNT
    append16(hdr, 4);   // ANCOUNT = 4 (PTR + SRV + TXT + A)
    append16(hdr, 0);   // NSCOUNT
    append16(hdr, 0);   // ARCOUNT

    return hdr + ptrRR + srvRR + txtRR + aRR;
}

void MdnsAnnouncer::sendPacket(const std::string& ifaddr, bool goodbye) {
    if (m_sock < 0) return;
    std::string pkt = buildResponse(ifaddr, false, 0, goodbye);

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(MDNS_PORT);
    inet_pton(AF_INET, MDNS_GROUP, &dest.sin_addr);

    ssize_t sent = sendto(m_sock, pkt.data(), pkt.size(), 0,
                          reinterpret_cast<struct sockaddr*>(&dest),
                          sizeof(dest));
    if (sent < 0) {
        LOGDEB("MdnsAnnouncer: sendto failed: " << strerror(errno) << "\n");
    }
}

void MdnsAnnouncer::handleQuery(const uint8_t* buf, int len,
                                 const struct sockaddr* from,
                                 socklen_t /*fromlen*/) {
    if (len < 12) return;

    // Quick sanity check: QR bit (bit 15 of flags) must be 0 (query)
    uint16_t flags = (static_cast<uint16_t>(buf[2]) << 8) | buf[3];
    if (flags & 0x8000) return; // it's a response, ignore

    uint16_t query_id = (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
    uint16_t qdcount  = (static_cast<uint16_t>(buf[4]) << 8) | buf[5];
    if (qdcount == 0) return;

    // Walk questions looking for our service type PTR query.
    // We do a naive text scan since we only care about one specific name.
    const std::string haystack(reinterpret_cast<const char*>(buf), len);
    const std::string needle = "_qobuz-connect";
    if (haystack.find(needle) == std::string::npos) return;

    // Resolve local IP
    std::string ifaddr = getIfaceAddr(m_iface);
    if (ifaddr.empty()) return;

    // Build and send targeted response unicast to querier
    std::string pkt = buildResponse(ifaddr, true, query_id, false);

    const auto* sa = static_cast<const struct sockaddr_in*>(
        reinterpret_cast<const void*>(from));

    // mDNS spec: if the query source port is 5353, respond multicast;
    // otherwise respond unicast to querier (legacy unicast query).
    if (ntohs(sa->sin_port) == MDNS_PORT) {
        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(MDNS_PORT);
        inet_pton(AF_INET, MDNS_GROUP, &dest.sin_addr);
        sendto(m_sock, pkt.data(), pkt.size(), 0,
               reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
    } else {
        sendto(m_sock, pkt.data(), pkt.size(), 0, from,
               sizeof(struct sockaddr_in));
    }
}

void MdnsAnnouncer::loop() {
    auto next_announce = std::chrono::steady_clock::now();

    while (!m_stop) {
        // Select with a 1-second timeout so we can check m_stop regularly
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(m_sock, &rfds);
        struct timeval tv{1, 0};
        int ret = select(m_sock + 1, &rfds, nullptr, nullptr, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            LOGERR("MdnsAnnouncer: select error: " << strerror(errno) << "\n");
            break;
        }

        // Handle incoming query
        if (ret > 0 && FD_ISSET(m_sock, &rfds)) {
            uint8_t buf[4096];
            struct sockaddr_storage from{};
            socklen_t fromlen = sizeof(from);
            ssize_t n = recvfrom(m_sock, buf, sizeof(buf), 0,
                                  reinterpret_cast<struct sockaddr*>(&from),
                                  &fromlen);
            if (n > 0) {
                handleQuery(buf, static_cast<int>(n),
                            reinterpret_cast<struct sockaddr*>(&from), fromlen);
            }
        }

        // Periodic re-announcement
        auto now = std::chrono::steady_clock::now();
        if (now >= next_announce) {
            std::string ifaddr = getIfaceAddr(m_iface);
            if (!ifaddr.empty()) {
                sendPacket(ifaddr, false);
                LOGDEB("MdnsAnnouncer: announced " << m_instance
                       << " at " << ifaddr << ":" << m_port << "\n");
            } else {
                LOGDEB("MdnsAnnouncer: no usable interface found, skipping\n");
            }
            next_announce = now + std::chrono::seconds(REANNOUNCE_INTERVAL_S);
        }
    }

    // Send goodbye packet (TTL=0) so the Qobuz app removes us immediately
    std::string ifaddr = getIfaceAddr(m_iface);
    if (!ifaddr.empty()) {
        sendPacket(ifaddr, true /*goodbye*/);
        LOGDEB("MdnsAnnouncer: sent goodbye for " << m_instance << "\n");
    }
}

} // namespace QConnect
