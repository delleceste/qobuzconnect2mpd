#include "qclog.hxx"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unistd.h>

std::ofstream g_qc_log_file;
std::mutex g_qc_log_mutex;
int g_qc_log_level = QConnect::QC_LOG_ERROR;

namespace {

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::string writeLog(const std::string& path, int level) {
    g_qc_log_file.open(path, std::ios::trunc);
    check(g_qc_log_file.is_open(), "could not open test log");
    g_qc_log_level = level;
    LOGINF("info message\n");
    LOGDEB("debug message\n");
    LOGTRC("trace message\n");
    g_qc_log_file.close();

    std::ifstream input(path);
    check(input.is_open(), "could not read test log");
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

} // namespace

int main() {
    char path_template[] = "/tmp/qconnect-qclog-test-XXXXXX";
    int fd = mkstemp(path_template);
    if (fd < 0) {
        std::cerr << "qconnect log test failed: could not create test log\n";
        return 1;
    }
    close(fd);
    const std::string path(path_template);
    try {
        std::string debug = writeLog(path, QConnect::QC_LOG_DEBUG);
        check(debug.find("[INF] info message") != std::string::npos,
              "debug level omitted info message");
        check(debug.find("[DEB] debug message") != std::string::npos,
              "debug level omitted debug message");
        check(debug.find("trace message") == std::string::npos,
              "debug level emitted trace message");

        std::string trace = writeLog(path, QConnect::QC_LOG_TRACE);
        check(trace.find("[DEB] debug message") != std::string::npos,
              "trace level omitted debug message");
        check(trace.find("[TRC] trace message") != std::string::npos,
              "trace level omitted trace message");
        std::remove(path.c_str());
        std::cout << "qconnect log levels passed\n";
        return 0;
    } catch (const std::exception& error) {
        g_qc_log_file.close();
        std::remove(path.c_str());
        std::cerr << "qconnect log test failed: " << error.what() << "\n";
        return 1;
    }
}
