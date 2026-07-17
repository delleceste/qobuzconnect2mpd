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

// qconnect2mpd: Qobuz Connect receiver daemon for upmpdcli.
//
// Reads configuration from the same file as upmpdcli (default:
// /etc/upmpdcli.conf).  Relevant keys:
//
//   qconnectfriendlyname   Device name shown in the Qobuz app
//                          (default: value of 'friendlyname')
//   qconnectdevicetype     Device type integer 1=Speaker (default: 1)
//   qconnectport           HTTP port for device endpoints (default: 9093)
//   qconnectformatid       Stream format: 5=MP3, 6=FLAC, 7=HiRes96, 27=HiRes192
//                          (default: value of 'qobuzformatid', else 27)
//   qconnectiface          Network interface to bind mDNS to (default: auto)
//   qconnectsockpath       Unix socket for IPC with upmpdcli
//                          (default: /var/run/upmpdcli-qconnect.sock)
//
//   # Qobuz API configuration (authentication uses browser OAuth):
//   qconnectappid          App ID          (falls back to qobuzappid)
//   qconnectcfvalue        App secret      (falls back to qobuzcfvalue)
//   qconnecttokenfile      OAuth token cache path (default: XDG/HOME data dir)
//
//   # MPD connection (reused from main upmpdcli config):
//   mpdhost / mpdport / mpdpassword
//
// Usage:
//   qconnect2mpd [-c configfile] [-d] [-v]
//     -c  path to upmpdcli config file
//     -d  daemonise (fork to background)
//     -v  enable debug logging (same as qconnectloglevel=debug)

#include "qcmgr.hxx"
#include "qclog.hxx"

#include <cctype>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <chrono>
#include <thread>
#include <unistd.h>

// Definitions for globals declared in qclog.hxx
std::ofstream g_qc_log_file;
std::mutex    g_qc_log_mutex;
int           g_qc_log_level = QConnect::QC_LOG_ERROR;

// ---- Minimal config-file reader --------------------------------------------
// We cannot link against libupnpp's conftree directly here (it carries the
// full libupnpp dependency).  Instead we ship a trimmed copy of the parser
// already present in the upmpdcli source tree as src/conftree.cpp/.h.
// We re-use it by forward-including its header.
#include "../conftree.h"

static volatile sig_atomic_t g_quit = 0;
static void sigHandler(int) { g_quit = 1; }

static std::string cfgGet(ConfSimple& cfg,
                            const std::string& key,
                            const std::string& dflt = {}) {
    std::string val;
    if (cfg.get(key, val)) return val;
    return dflt;
}

static int cfgGetInt(ConfSimple& cfg, const std::string& key, int dflt) {
    std::string val;
    if (cfg.get(key, val) && !val.empty()) {
        try { return std::stoi(val); } catch (...) {}
    }
    return dflt;
}

// ---- Entry point ------------------------------------------------------------

int main(int argc, char* argv[]) {
    std::string config_file = "/etc/upmpdcli.conf";
    std::string status_file_arg;
    bool daemonise = false;
    bool debug_logging = false;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            config_file = argv[++i];
        } else if (!strcmp(argv[i], "-d")) {
            daemonise = true;
        } else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
            status_file_arg = argv[++i];
        } else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--debug")) {
            debug_logging = true;
        } else {
            std::cerr << "Usage: " << argv[0]
                      << " [-c configfile] [-d] [-o statusfile] [-v|--debug]\n";
            return 1;
        }
    }

    if (daemonise) {
        if (daemon(0, 0) < 0) {
            std::cerr << "daemon() failed: " << strerror(errno) << "\n";
            return 1;
        }
    }

    signal(SIGTERM, sigHandler);
    signal(SIGINT,  sigHandler);
    signal(SIGPIPE, SIG_IGN);

    // ---- Load config -------------------------------------------------------
    ConfSimple cfg(config_file.c_str(), 1 /* readonly */);

    using namespace QConnect;

    auto parseLogLevel = [](std::string value, int fallback) -> int {
        for (char& c : value) {
            c = static_cast<char>(
                std::tolower(static_cast<unsigned char>(c)));
        }
        if (value == "0" || value == "error" || value == "err")
            return QC_LOG_ERROR;
        if (value == "1" || value == "info" || value == "inf")
            return QC_LOG_INFO;
        if (value == "2" || value == "debug" || value == "deb")
            return QC_LOG_DEBUG;
        return fallback;
    };
    g_qc_log_level = parseLogLevel(
        cfgGet(cfg, "qconnectloglevel", "error"), QC_LOG_ERROR);
    if (const char* level = std::getenv("QC_LOGLEVEL"); level && *level)
        g_qc_log_level = parseLogLevel(level, g_qc_log_level);
    if (const char* debug = std::getenv("QC_DEBUG");
        debug && *debug && std::string(debug) != "0") {
        g_qc_log_level = QC_LOG_DEBUG;
    }
    if (debug_logging)
        g_qc_log_level = QC_LOG_DEBUG;

    QcConfig qcfg;

    // Device identity
    std::string base_name = cfgGet(cfg, "friendlyname", "UpMpd");
    qcfg.friendly_name = cfgGet(cfg, "qconnectfriendlyname", base_name);
    qcfg.device_type   = cfgGetInt(cfg, "qconnectdevicetype", 1);

    // Audio quality
    int base_fmt = cfgGetInt(cfg, "qobuzformatid", 27);
    qcfg.format_id = cfgGetInt(cfg, "qconnectformatid", base_fmt);

    // HTTP port
    qcfg.http_port = cfgGetInt(cfg, "qconnectport", 9093);

    // Network interface
    qcfg.iface = cfgGet(cfg, "qconnectiface");

    // IPC socket — empty disables IPC (requires upmpdcli Phase 2 integration)
    qcfg.upmpdcli_sock = cfgGet(cfg, "qconnectsockpath", "");

    // MPD
    qcfg.mpd_host     = cfgGet(cfg, "mpdhost", "localhost");
    qcfg.mpd_port     = cfgGetInt(cfg, "mpdport", 6600);
    qcfg.mpd_password = cfgGet(cfg, "mpdpassword");

    // Status file: -o takes precedence over config key qconnectstatusfile
    qcfg.status_file = status_file_arg.empty()
                       ? cfgGet(cfg, "qconnectstatusfile")
                       : status_file_arg;

    // Log file — open early so startup messages are captured
    {
        std::string log_path = cfgGet(cfg, "qconnectlogfile");
        if (!log_path.empty()) {
            g_qc_log_file.open(log_path, std::ios::trunc);
            if (!g_qc_log_file)
                std::cerr << "qconnect2mpd: cannot open log file: " << log_path << "\n";
            else
                LOGINF("qconnect2mpd: log opened\n");
        }
    }

    LOGSTD("qconnect2mpd: config: " << config_file
           << (cfg.ok() ? "" : " (not found — using defaults)") << "\n");
    LOGSTD("qconnect2mpd: MPD " << qcfg.mpd_host << ":" << qcfg.mpd_port << "\n");
    if (!qcfg.status_file.empty())
        LOGSTD("qconnect2mpd: status file: " << qcfg.status_file << "\n");

    // Qobuz API identity. User authentication is OAuth-only.
    qcfg.app_id       = cfgGet(cfg, "qconnectappid",
                                 cfgGet(cfg, "qobuzappid"));
    qcfg.app_secret   = cfgGet(cfg, "qconnectcfvalue",
                                 cfgGet(cfg, "qobuzcfvalue"));
    qcfg.token_file   = cfgGet(cfg, "qconnecttokenfile");

    // UUID: persist across restarts by reading/writing a state file
    std::string state_path = cfgGet(cfg, "cachedir",
                                     "/var/cache/upmpdcli")
                             + "/qconnect.uuid";
    {
        std::ifstream sf(state_path);
        if (sf) std::getline(sf, qcfg.uuid);
    }
    // QcManager generates a UUID if empty; save it after creation

    // ---- Start manager -----------------------------------------------------
    QcManager mgr(qcfg);

    // Persist the (possibly new) UUID
    {
        // Re-read the uuid after manager constructor may have generated it
        // We can't easily access it from here, so just write after start.
    }

    if (!mgr.start()) {
        std::cerr << "qconnect2mpd: startup failed\n";
        return 1;
    }

    LOGINF("qconnect2mpd: started, UUID=" << mgr.uuid() << "\n");

    // Persist UUID to state file (may have been generated by QcManager)
    {
        std::ofstream sf(state_path);
        if (sf) sf << mgr.uuid() << "\n";
    }

    // ---- Main loop ---------------------------------------------------------
    while (!g_quit && !mgr.hasFatalError()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    if (mgr.hasFatalError()) {
        LOGERR("qconnect2mpd: WebSocket connection lost — exiting (systemd will restart)\n");
        mgr.stop();
        return 1;
    }
    LOGINF("qconnect2mpd: shutting down\n");
    mgr.stop();
    return 0;
}
