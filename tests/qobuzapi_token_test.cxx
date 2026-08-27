#include "qobuzapi.hxx"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

std::ofstream g_qc_log_file;
std::mutex g_qc_log_mutex;
int g_qc_log_level = 2;

namespace {

bool check(bool condition, const char* expression, int line) {
    if (condition) return true;
    std::cerr << "Qobuz token test failed at line " << line << ": "
              << expression << '\n';
    return false;
}

#define CHECK(expr) do { if (!check((expr), #expr, __LINE__)) return false; } while (0)

bool writeFile(const std::string& path, const std::string& contents,
               mode_t mode) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return false;
    size_t offset = 0;
    while (offset < contents.size()) {
        ssize_t written = ::write(fd, contents.data() + offset,
                                  contents.size() - offset);
        if (written <= 0) {
            ::close(fd);
            return false;
        }
        offset += static_cast<size_t>(written);
    }
    return ::close(fd) == 0;
}

std::string readFile(const std::string& path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream),
            std::istreambuf_iterator<char>()};
}

std::string md5Hex(const std::string& value) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) return {};
    const bool ok = EVP_DigestInit_ex(context, EVP_md5(), nullptr) == 1 &&
                    EVP_DigestUpdate(context, value.data(), value.size()) == 1 &&
                    EVP_DigestFinal_ex(context, digest, &digest_size) == 1;
    EVP_MD_CTX_free(context);
    if (!ok) return {};
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digest_size; ++i)
        stream << std::setw(2) << static_cast<unsigned>(digest[i]);
    return stream.str();
}

std::string queryValue(const std::string& target, const std::string& name) {
    const std::string key = name + "=";
    size_t position = target.find('?');
    while (position != std::string::npos && position < target.size()) {
        ++position;
        if (target.compare(position, key.size(), key) == 0) {
            const size_t end = target.find('&', position);
            return target.substr(position + key.size(), end - position - key.size());
        }
        position = target.find('&', position);
    }
    return {};
}

class MockQobuzServer {
public:
    ~MockQobuzServer() { stop(); }

    bool start() {
        m_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (m_fd < 0) return false;
        int one = 1;
        (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(m_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(m_fd, 4) != 0)
            return false;
        socklen_t address_size = sizeof(address);
        if (::getsockname(m_fd, reinterpret_cast<sockaddr*>(&address),
                          &address_size) != 0)
            return false;
        m_port = ntohs(address.sin_port);
        m_thread = std::thread([this] { serve(); });
        return true;
    }

    void stop() {
        m_stop = true;
        if (m_fd >= 0) (void)::shutdown(m_fd, SHUT_RDWR);
        if (m_thread.joinable()) m_thread.join();
        if (m_fd >= 0) ::close(m_fd);
        m_fd = -1;
    }

    int port() const { return m_port; }
    const std::vector<std::string>& targets() const { return m_targets; }
    bool authenticated() const { return m_authenticated; }
    bool validClassicSignature() const { return m_valid_classic_signature; }

private:
    static std::string readRequest(int client) {
        std::string request;
        size_t body_size = 0;
        size_t header_end = std::string::npos;
        char buffer[4096];
        while (request.size() < 64 * 1024) {
            const ssize_t count = ::recv(client, buffer, sizeof(buffer), 0);
            if (count <= 0) break;
            request.append(buffer, static_cast<size_t>(count));
            if (header_end == std::string::npos) {
                header_end = request.find("\r\n\r\n");
                if (header_end != std::string::npos) {
                    const std::string headers = request.substr(0, header_end);
                    const std::string marker = "Content-Length:";
                    const size_t length_at = headers.find(marker);
                    if (length_at != std::string::npos) {
                        const size_t value_at = length_at + marker.size();
                        body_size = static_cast<size_t>(
                            std::strtoul(headers.c_str() + value_at, nullptr, 10));
                    }
                }
            }
            if (header_end != std::string::npos &&
                request.size() >= header_end + 4 + body_size)
                break;
        }
        return request;
    }

    static void sendResponse(int client, int status, const std::string& body) {
        const char* reason = status == 200 ? "OK" :
                             status == 400 ? "Bad Request" : "Not Found";
        std::ostringstream response;
        response << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
                 << "Content-Type: application/json\r\n"
                 << "Content-Length: " << body.size() << "\r\n"
                 << "Connection: close\r\n\r\n" << body;
        const std::string bytes = response.str();
        size_t sent = 0;
        while (sent < bytes.size()) {
            const ssize_t count = ::send(client, bytes.data() + sent,
                                         bytes.size() - sent, 0);
            if (count <= 0) break;
            sent += static_cast<size_t>(count);
        }
    }

    void serve() {
        while (!m_stop.load()) {
            sockaddr_in peer{};
            socklen_t peer_size = sizeof(peer);
            const int client = ::accept(
                m_fd, reinterpret_cast<sockaddr*>(&peer), &peer_size);
            if (client < 0) return;
            const std::string request = readRequest(client);
            const size_t first_space = request.find(' ');
            const size_t second_space = first_space == std::string::npos
                ? std::string::npos : request.find(' ', first_space + 1);
            const std::string target = second_space == std::string::npos
                ? std::string() : request.substr(first_space + 1,
                                                  second_space - first_space - 1);
            m_targets.push_back(target);
            if (request.find("\r\nX-User-Auth-Token: test-oauth-token\r\n") ==
                std::string::npos)
                m_authenticated = false;

            int status = 404;
            std::string body = R"({"error":"unexpected request"})";
            if (target == "/session/start") {
                status = 200;
                body = R"({"session_id":"test-session","expires_at":4102444800,"infos":"unused"})";
            } else if (target.rfind("/file/url?", 0) == 0) {
                // A valid but unusable /file/url response must fall back to the
                // classic endpoint only after the preferred endpoint was tried.
                status = 200;
                body = "{}";
            } else if (target.rfind("/track/getFileUrl?", 0) == 0) {
                const std::string timestamp = queryValue(target, "request_ts");
                const std::string format = queryValue(target, "format_id");
                const std::string plain = "trackgetFileUrlformat_id" + format +
                    "intentstreamtrack_id12345" + timestamp + "classic-secret";
                const bool valid_signature =
                    !timestamp.empty() &&
                    queryValue(target, "request_sig") == md5Hex(plain);
                m_valid_classic_signature =
                    m_valid_classic_signature && valid_signature;
                if (!valid_signature) {
                    status = 400;
                    body = R"({"error":"bad signature"})";
                } else if (format == "6") {
                    // An accepted signature can still return 404 for a format.
                    // The client should cache that secret and try format 5.
                    status = 404;
                    body = R"({"error":"format unavailable"})";
                } else {
                    status = 200;
                    body = R"({"url":"https://cdn.example/track.mp3","mime_type":"audio/mpeg","format_id":5,"duration":123,"sampling_rate":44.1,"bit_depth":16})";
                }
            }
            sendResponse(client, status, body);
            ::close(client);
            if (target.rfind("/track/getFileUrl?", 0) == 0 &&
                queryValue(target, "format_id") == "5")
                return;
        }
    }

    int m_fd{-1};
    int m_port{-1};
    std::atomic<bool> m_stop{false};
    std::thread m_thread;
    std::vector<std::string> m_targets;
    bool m_authenticated{true};
    bool m_valid_classic_signature{true};
};

bool testSecureTokenFiles() {
    namespace fs = std::filesystem;
    std::vector<char> pattern{
        '/', 't', 'm', 'p', '/', 'q', 'c', 'o', 'n', 'n', 'e', 'c', 't',
        '-', 't', 'o', 'k', 'e', 'n', '-', 't', 'e', 's', 't', '.', 'X',
        'X', 'X', 'X', 'X', 'X', '\0'};
    char* made = ::mkdtemp(pattern.data());
    CHECK(made != nullptr);
    const fs::path directory(made);
    const fs::path seed = directory / "seed";
    const fs::path saved = directory / "saved";
    const fs::path sentinel = directory / "sentinel";
    const fs::path linked_parent = directory / "linked-parent";

    CHECK(writeFile(seed.string(), "test-oauth-token\n", 0644));
    QConnect::QobuzApi api("https://invalid.example", "app", "secret");
    CHECK(api.loadToken(seed.string()));
    CHECK(api.userToken() == "test-oauth-token");

    struct stat seed_stat{};
    CHECK(::stat(seed.c_str(), &seed_stat) == 0);
    CHECK((seed_stat.st_mode & 0777) == 0600);
    CHECK(seed_stat.st_uid == ::geteuid());

    CHECK(writeFile(sentinel.string(), "sentinel", 0600));
    CHECK(::symlink(sentinel.c_str(), saved.c_str()) == 0);
    CHECK(api.saveToken(saved.string()));
    CHECK(readFile(sentinel.string()) == "sentinel");
    CHECK(readFile(saved.string()) == "test-oauth-token");

    struct stat saved_stat{};
    CHECK(::lstat(saved.c_str(), &saved_stat) == 0);
    CHECK(S_ISREG(saved_stat.st_mode));
    CHECK((saved_stat.st_mode & 0777) == 0600);
    CHECK(saved_stat.st_uid == ::geteuid());

    CHECK(::symlink(directory.c_str(), linked_parent.c_str()) == 0);
    CHECK(!api.saveToken((linked_parent / "token").string()));

    const fs::path fifo = directory / "fifo";
    CHECK(::mkfifo(fifo.c_str(), 0600) == 0);
    CHECK(!api.loadToken(fifo.string()));

    std::error_code error;
    fs::remove_all(directory, error);
    CHECK(!error);
    return true;
}

// The direct endpoint must be tried first and must not open a CMAF stream
// session at all: only direct CDN URLs carry the Content-Length and byte
// ranges that MusicPD's FLAC decoder needs in order to seek.
bool testDirectApiPrecedesSegmentedFallback() {
    namespace fs = std::filesystem;
    std::vector<char> pattern{
        '/', 't', 'm', 'p', '/', 'q', 'c', 'o', 'n', 'n', 'e', 'c', 't',
        '-', 'a', 'p', 'i', '-', 't', 'e', 's', 't', '.', 'X', 'X', 'X',
        'X', 'X', 'X', '\0'};
    char* made = ::mkdtemp(pattern.data());
    CHECK(made != nullptr);
    const fs::path directory(made);
    const fs::path token = directory / "token";
    CHECK(writeFile(token.string(), "test-oauth-token\n", 0600));

    MockQobuzServer server;
    CHECK(server.start());
    QConnect::QobuzApi api(
        "http://127.0.0.1:" + std::to_string(server.port()),
        "test-app", "classic-secret");
    QConnect::TrackStreamInfo info;
    CHECK(!api.getStreamUrl(12345, 6, info));
    CHECK(api.loadToken(token.string()));
    info.local_path = "/stale";
    info.segment_token = "stale";
    CHECK(api.getStreamUrl(12345, 6, info));
    server.stop();

    // Default mode is Direct: no /session/start, no /file/url.
    CHECK(server.targets().size() == 2);
    CHECK(server.targets()[0].rfind("/track/getFileUrl?", 0) == 0);
    CHECK(queryValue(server.targets()[0], "format_id") == "6");
    CHECK(server.targets()[1].rfind("/track/getFileUrl?", 0) == 0);
    CHECK(queryValue(server.targets()[1], "format_id") == "5");
    CHECK(server.authenticated());
    CHECK(server.validClassicSignature());
    CHECK(info.stream_url == "https://cdn.example/track.mp3");
    CHECK(info.local_path.empty());
    CHECK(info.segment_token.empty());
    CHECK(info.duration_ms == 123000);
    CHECK(info.format_id == 5);
    CHECK(info.sampling_rate == 44100);
    CHECK(info.bit_depth == 16);

    std::error_code error;
    fs::remove_all(directory, error);
    CHECK(!error);
    return true;
}

// 'auto' keeps the CMAF path reachable, but still only after the direct
// endpoint has been given the same format.
bool testAutoModeFallsBackToSegmented() {
    namespace fs = std::filesystem;
    std::vector<char> pattern{
        '/', 't', 'm', 'p', '/', 'q', 'c', 'o', 'n', 'n', 'e', 'c', 't',
        '-', 'a', 'u', 't', 'o', '-', 't', 'e', 's', 't', '.', 'X', 'X',
        'X', 'X', 'X', 'X', '\0'};
    char* made = ::mkdtemp(pattern.data());
    CHECK(made != nullptr);
    const fs::path directory(made);
    const fs::path token = directory / "token";
    CHECK(writeFile(token.string(), "test-oauth-token\n", 0600));

    MockQobuzServer server;
    CHECK(server.start());
    QConnect::QobuzApi api(
        "http://127.0.0.1:" + std::to_string(server.port()),
        "test-app", "classic-secret");
    api.setStreamMode(QConnect::StreamMode::Auto);
    CHECK(api.loadToken(token.string()));
    QConnect::TrackStreamInfo info;
    CHECK(api.getStreamUrl(12345, 6, info));
    server.stop();

    CHECK(server.targets().size() == 4);
    CHECK(server.targets()[0] == "/session/start");
    CHECK(server.targets()[1].rfind("/track/getFileUrl?", 0) == 0);
    CHECK(queryValue(server.targets()[1], "format_id") == "6");
    CHECK(server.targets()[2].rfind("/file/url?", 0) == 0);
    CHECK(queryValue(server.targets()[2], "format_id") == "6");
    CHECK(server.targets()[3].rfind("/track/getFileUrl?", 0) == 0);
    CHECK(queryValue(server.targets()[3], "format_id") == "5");
    CHECK(info.stream_url == "https://cdn.example/track.mp3");

    std::error_code error;
    fs::remove_all(directory, error);
    CHECK(!error);
    return true;
}

// A default-constructed client must never reach for a stream session, so a
// Qobuz-side CMAF change cannot silently reintroduce unseekable playback.
bool testStreamModeParsing() {
    CHECK(QConnect::streamModeFromString("direct") == QConnect::StreamMode::Direct);
    CHECK(QConnect::streamModeFromString("auto") == QConnect::StreamMode::Auto);
    CHECK(QConnect::streamModeFromString("segmented") == QConnect::StreamMode::Segmented);
    CHECK(QConnect::streamModeFromString("") == QConnect::StreamMode::Direct);
    CHECK(QConnect::streamModeFromString("nonsense") == QConnect::StreamMode::Direct);
    CHECK(std::string(QConnect::streamModeName(QConnect::StreamMode::Direct)) == "direct");
    CHECK(std::string(QConnect::streamModeName(QConnect::StreamMode::Auto)) == "auto");
    CHECK(std::string(QConnect::streamModeName(QConnect::StreamMode::Segmented)) == "segmented");
    return true;
}

} // namespace

int main() {
    return testSecureTokenFiles() &&
           testStreamModeParsing() &&
           testDirectApiPrecedesSegmentedFallback() &&
           testAutoModeFallsBackToSegmented()
        ? EXIT_SUCCESS : EXIT_FAILURE;
}
