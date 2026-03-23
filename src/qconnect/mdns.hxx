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
#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <cstdint>
#include <sys/socket.h>

namespace QConnect {

// Announces a Qobuz Connect device via mDNS on the local network.
//
// Advertises the service type "_qobuz-connect._tcp.local." with the
// following records:
//   PTR  _qobuz-connect._tcp.local.  ->  <instance>._qobuz-connect._tcp.local.
//   SRV  <instance>._qobuz-connect._tcp.local.  ->  <host>.local.  port=<port>
//   TXT  <instance>._qobuz-connect._tcp.local.  ->  key=value pairs
//   A    <host>.local.  ->  <ip>
//
// The Qobuz app has a quirk: it only processes the first PTR record in
// batched mDNS responses.  We work around this by re-announcing every 5 s
// (same workaround used by qonductor).
//
// Queries to "_qobuz-connect._tcp.local." PTR are answered with the full
// record set (PTR + SRV + TXT + A in the additional section).

class MdnsAnnouncer {
public:
    // uuid:     lowercase UUID string, e.g. "550e8400-e29b-41d4-a716-446655440000"
    //           Used as the mDNS instance name and in TXT path=/devices/<uuid>
    // name:     human-readable device name, e.g. "UpMpd Living Room"
    // port:     TCP port of the HTTP device-endpoint server
    // iface:    network interface name to bind to (empty = auto-detect first
    //           non-loopback interface)
    MdnsAnnouncer(const std::string& uuid,
                  const std::string& name,
                  int                port,
                  const std::string& iface = "");
    ~MdnsAnnouncer();

    // Start the announcement thread.  Returns false if the socket could not
    // be created (e.g. no suitable network interface found).
    bool start();

    // Stop the announcement thread and send a goodbye packet (TTL=0).
    void stop();

    // True if start() succeeded and stop() has not yet been called.
    bool running() const { return m_running.load(); }

private:
    void    loop();
    bool    openSocket();
    void    sendPacket(const std::string& ifaddr, bool goodbye);
    void    handleQuery(const uint8_t* buf, int len,
                        const struct sockaddr* from, socklen_t fromlen);

    // DNS packet builders
    // Returns packed DNS response bytes.
    std::string buildResponse(const std::string& ifaddr,
                               bool is_answer_to_query,
                               uint16_t query_id,
                               bool goodbye) const;

    std::string m_uuid;       // lowercase UUID without braces
    std::string m_name;       // friendly name (used as mDNS instance label)
    int         m_port;
    std::string m_iface;      // interface name (may be empty)
    std::string m_hostname;   // <sanitised-name>.local
    std::string m_instance;   // <friendly-name>._qobuz-connect._tcp.local.

    int              m_sock{-1};
    std::thread      m_thread;
    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_running{false};

    static constexpr int    REANNOUNCE_INTERVAL_S = 5;
    static constexpr uint32_t TTL_PTR = 4500;
    static constexpr uint32_t TTL_SRV = 120;
    static constexpr uint32_t TTL_TXT = 4500;
    static constexpr uint32_t TTL_A   = 120;
};

} // namespace QConnect
