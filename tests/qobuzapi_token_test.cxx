#include "qobuzapi.hxx"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

std::ofstream g_qc_log_file;
std::mutex g_qc_log_mutex;

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

} // namespace

int main() {
    return testSecureTokenFiles() ? EXIT_SUCCESS : EXIT_FAILURE;
}
