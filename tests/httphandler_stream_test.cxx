#include "httphandler.hxx"
#include "segstream.hxx"

#include <curl/curl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

std::ofstream g_qc_log_file;
std::mutex g_qc_log_mutex;
int g_qc_log_level = 2;

namespace {

bool check(bool condition, const char* expression, int line) {
    if (condition) return true;
    std::cerr << "HTTP stream test failed at line " << line << ": "
              << expression << '\n';
    return false;
}

#define CHECK(expr) do { if (!check((expr), #expr, __LINE__)) return false; } while (0)

int reservePort() {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        return -1;
    }
    socklen_t length = sizeof(address);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        ::close(fd);
        return -1;
    }
    const int port = ntohs(address.sin_port);
    ::close(fd);
    return port;
}

class StalledHttpServer {
public:
    bool start() {
        m_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (m_fd < 0) return false;
        int one = 1;
        ::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(m_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(m_fd, 2) != 0)
            return false;
        socklen_t length = sizeof(address);
        if (::getsockname(m_fd, reinterpret_cast<sockaddr*>(&address), &length) != 0)
            return false;
        m_port = ntohs(address.sin_port);
        m_thread = std::thread([this] {
            sockaddr_in peer{};
            socklen_t peer_length = sizeof(peer);
            const int client = ::accept(
                m_fd, reinterpret_cast<sockaddr*>(&peer), &peer_length);
            m_client.store(client, std::memory_order_release);
            if (client < 0) return;
            char buffer[1024];
            (void)::recv(client, buffer, sizeof(buffer), 0);
            while (!m_stop.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
        });
        return true;
    }

    ~StalledHttpServer() { stop(); }

    int port() const { return m_port; }

    void stop() {
        m_stop = true;
        const int client = m_client.load(std::memory_order_acquire);
        if (client >= 0) ::shutdown(client, SHUT_RDWR);
        if (m_fd >= 0) ::shutdown(m_fd, SHUT_RDWR);
        if (m_thread.joinable()) m_thread.join();
        const int accepted = m_client.exchange(-1, std::memory_order_acq_rel);
        if (accepted >= 0) ::close(accepted);
        if (m_fd >= 0) ::close(m_fd);
        m_fd = -1;
    }

private:
    int m_fd{-1};
    std::atomic<int> m_client{-1};
    int m_port{-1};
    std::atomic<bool> m_stop{false};
    std::thread m_thread;
};

struct HttpResult {
    CURLcode curl_code{CURLE_OK};
    long status{0};
    std::string body;
    std::map<std::string, std::string> headers;
};

size_t bodyCallback(char* data, size_t size, size_t count, void* userdata) {
    const size_t bytes = size * count;
    static_cast<std::string*>(userdata)->append(data, bytes);
    return bytes;
}

size_t headerCallback(char* data, size_t size, size_t count, void* userdata) {
    const size_t bytes = size * count;
    std::string line(data, bytes);
    const auto colon = line.find(':');
    if (colon == std::string::npos) return bytes;
    std::string name = line.substr(0, colon);
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::string value = line.substr(colon + 1);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
        value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
        value.pop_back();
    static_cast<HttpResult*>(userdata)->headers[name] = value;
    return bytes;
}

HttpResult request(const std::string& url, bool head,
                   const char* range = nullptr) {
    HttpResult result;
    CURL* curl = curl_easy_init();
    if (!curl) {
        result.curl_code = CURLE_FAILED_INIT;
        return result;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOBODY, head ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bodyCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &result);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    if (range) curl_easy_setopt(curl, CURLOPT_RANGE, range);
    result.curl_code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.status);
    curl_easy_cleanup(curl);
    return result;
}

HttpResult post(const std::string& url, const std::string& body) {
    HttpResult result;
    CURL* curl = curl_easy_init();
    if (!curl) {
        result.curl_code = CURLE_FAILED_INIT;
        return result;
    }
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Expect:");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                     static_cast<curl_off_t>(body.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bodyCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    result.curl_code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return result;
}

std::shared_ptr<QConnect::SegmentedTrackPlan>
makePlan(uint32_t track_id, const std::string& bytes) {
    auto plan = std::make_shared<QConnect::SegmentedTrackPlan>();
    plan->track_id = track_id;
    plan->format_id = 6;
    plan->flac_header.assign(bytes.begin(), bytes.end());
    plan->total_bytes = bytes.size();
    return plan;
}

bool testHttpStreamHeadersAndRanges() {
    using namespace QConnect;
    const int port = reservePort();
    CHECK(port > 0);

    SegmentedTrackRegistry registry;
    std::atomic<int> connect_calls{0};
    std::atomic<int> oauth_calls{0};
    std::atomic<bool> oauth_block_started{false};
    std::atomic<bool> oauth_block_release{false};
    HttpHandler http("test-device", "test", port, 6, "test-app",
                     [&](ConnectCredentials) { ++connect_calls; });
    http.setSegmentedRegistry(&registry);
    const std::string oauth_path =
        "/oauth/callback/0123456789abcdef0123456789abcdef";
    http.setOAuthCallback(
        oauth_path,
        [&](const std::string& code) {
            ++oauth_calls;
            if (code == "blocked") {
                oauth_block_started = true;
                while (!oauth_block_release.load())
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                return false;
            }
            return code == "accepted";
        });
    CHECK(http.start());

    auto exact_plan = makePlan(301, "fLaC-exact-body");
    const auto exact_token = SegmentedTrackRegistry::tokenForTrack(301, 6);
    registry.registerPlan(exact_token, exact_plan);
    auto exact_handle = acquireSegmentedTrackDownload(exact_plan);
    uint64_t exact_size = 0;
    CHECK(waitForSegmentedTrack(exact_handle, exact_size, 2000));
    releaseSegmentedTrackDownload(exact_handle);

    const std::string base = "http://127.0.0.1:" + std::to_string(port) +
                             "/qobuz-segmented/";
    const std::string device_base = "http://127.0.0.1:" +
        std::to_string(port) + "/devices/test-device/";
    const std::string server_base = "http://127.0.0.1:" +
        std::to_string(port);
    const std::string oauth_base = server_base + oauth_path +
        "?code_autorisation=";

    auto public_oauth = request(
        server_base + "/oauth/callback?code_autorisation=accepted", false);
    CHECK(public_oauth.curl_code == CURLE_OK);
    CHECK(public_oauth.status == 404);

    HttpResult blocked_oauth;
    std::thread blocked_request([&] {
        blocked_oauth = request(oauth_base + "blocked", false);
    });
    const auto block_deadline = std::chrono::steady_clock::now() +
                                std::chrono::seconds(2);
    while (!oauth_block_started.load() &&
           std::chrono::steady_clock::now() < block_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    auto oauth_busy = request(oauth_base + "accepted", false);
    oauth_block_release = true;
    blocked_request.join();
    CHECK(oauth_block_started.load());
    CHECK(oauth_busy.curl_code == CURLE_OK);
    CHECK(oauth_busy.status == 409);
    CHECK(blocked_oauth.curl_code == CURLE_OK);
    CHECK(blocked_oauth.status == 500);
    CHECK(oauth_calls.load() == 1);

    auto oauth_fail = request(oauth_base + "rejected", false);
    CHECK(oauth_fail.curl_code == CURLE_OK);
    CHECK(oauth_fail.status == 500);
    CHECK(oauth_fail.body.find("Login failed") != std::string::npos);

    auto oauth_ok = request(oauth_base + "accepted", false);
    CHECK(oauth_ok.curl_code == CURLE_OK);
    CHECK(oauth_ok.status == 200);
    CHECK(oauth_ok.body.find("Login successful") != std::string::npos);
    CHECK(oauth_calls.load() == 3);

    auto oauth_reuse = request(oauth_base + "accepted", false);
    CHECK(oauth_reuse.curl_code == CURLE_OK);
    CHECK(oauth_reuse.status == 404);
    CHECK(oauth_calls.load() == 3);

    auto oversized = post(device_base + "connect-to-qconnect",
                           std::string(1024 * 1024 + 1, 'x'));
    CHECK(oversized.curl_code == CURLE_OK);
    CHECK(oversized.status == 413);
    CHECK(connect_calls.load() == 0);

    auto valid_post = post(device_base + "connect-to-qconnect",
                           R"({"session_id":"test"})");
    CHECK(valid_post.curl_code == CURLE_OK);
    CHECK(valid_post.status == 200);
    CHECK(connect_calls.load() == 1);

    auto full = request(base + exact_token, false);
    CHECK(full.curl_code == CURLE_OK);
    CHECK(full.status == 200);
    CHECK(full.body == "fLaC-exact-body");
    CHECK(full.headers["accept-ranges"] == "bytes");
    CHECK(full.headers["content-length"] == std::to_string(exact_size));

    auto suffix = request(base + exact_token, false, "-4");
    CHECK(suffix.curl_code == CURLE_OK);
    CHECK(suffix.status == 206);
    CHECK(suffix.body == "body");
    CHECK(suffix.headers["content-range"] ==
          "bytes " + std::to_string(exact_size - 4) + "-" +
          std::to_string(exact_size - 1) + "/" + std::to_string(exact_size));

    StalledHttpServer stalled;
    CHECK(stalled.start());
    auto growing_plan = makePlan(302, "fLaC");
    growing_plan->segment_byte_lens = {1};
    growing_plan->url_template = "http://127.0.0.1:" +
        std::to_string(stalled.port()) + "/$SEGMENT$";
    const auto growing_token = SegmentedTrackRegistry::tokenForTrack(302, 6);
    registry.registerPlan(growing_token, growing_plan);

    const auto malformed_started = std::chrono::steady_clock::now();
    auto malformed = request(base + growing_token, false, "not-a-range");
    CHECK(malformed.curl_code == CURLE_OK);
    CHECK(malformed.status == 400);
    CHECK(std::chrono::steady_clock::now() - malformed_started <
          std::chrono::seconds(2));

    auto head = request(base + growing_token, true);
    CHECK(head.curl_code == CURLE_OK);
    CHECK(head.status == 200);
    CHECK(head.headers["accept-ranges"] == "bytes");
    CHECK(head.headers.find("content-length") == head.headers.end());

    registry.clear();
    stalled.stop();
    http.stop();
    return true;
}

} // namespace

int main() {
    return testHttpStreamHeadersAndRanges() ? EXIT_SUCCESS : EXIT_FAILURE;
}
