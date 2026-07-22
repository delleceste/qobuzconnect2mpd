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
//   qconnectmdnsrequired   Fail startup if mDNS can't announce (default: true;
//                          set false for cloud-only operation)
//
//   # Persistent state (OAuth token + device UUID) — one directory:
//   qconnectstatedir       Directory holding user_token and device.uuid.
//                          Set this for a service account (the standard). If
//                          unset, an interactive run falls back to
//                          $XDG_STATE_HOME/qobuzconnect2mpd or
//                          ~/.local/state/qobuzconnect2mpd; a service with it
//                          unset aborts asking you to set it. Created if missing.
//
//   # Qobuz API configuration (authentication uses browser OAuth):
//   qconnectappid          App ID          (falls back to qobuzappid)
//   qconnectcfvalue        App secret      (falls back to qobuzcfvalue)
//   qconnecttokenfile      OAuth token path (default: <qconnectstatedir>/user_token)
//
//   # MPD connection (reused from main upmpdcli config):
//   mpdhost / mpdport / mpdpassword
//
// Usage:
//   qconnect2mpd [-c configfile] [-d] [-L] [-o statusfile] [-v|-vv]
//     -c  path to upmpdcli config file
//     -d  daemonise (fork to background)
//     -L  bootstrap: complete the browser OAuth login, cache the token, exit
//     -o  now-playing status file path
//     -v  enable debug logging (same as qconnectloglevel=debug)
//     -vv enable high-frequency trace logging

#include "qcmgr.hxx"
#include "qclog.hxx"

#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <chrono>
#include <thread>
#include <sys/stat.h>
#include <sys/types.h>
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

static bool cfgGetBool(ConfSimple& cfg, const std::string& key, bool dflt) {
    std::string val;
    if (!cfg.get(key, val) || val.empty()) return dflt;
    for (char& c : val) c = static_cast<char>(std::tolower(
                                static_cast<unsigned char>(c)));
    return !(val == "0" || val == "false" || val == "no" || val == "off");
}

// Create a directory and any missing parents (like `mkdir -p`), mode 0700.
static bool makeDirs(const std::string& path, mode_t mode) {
    if (path.empty()) return false;
    for (size_t i = 1; i < path.size(); ++i) {
        if (path[i] == '/') {
            std::string sub = path.substr(0, i);
            if (::mkdir(sub.c_str(), mode) != 0 && errno != EEXIST) return false;
        }
    }
    return ::mkdir(path.c_str(), mode) == 0 || errno == EEXIST;
}

// Resolve the single directory that holds all persistent per-device state
// (the OAuth token and the device UUID). An explicit 'qconnectstatedir' wins;
// otherwise fall back to the XDG state location for an interactive user only.
static std::string resolveStateDir(ConfSimple& cfg) {
    // A service account sets this explicitly (the documented standard); it is
    // used verbatim, with no home/XDG guessing.
    std::string configured = cfgGet(cfg, "qconnectstatedir");
    if (!configured.empty()) return configured;
    // Fallback only for an interactive user running the daemon by hand: the XDG
    // state location under their real home. A nologin service account has no
    // meaningful home here, so it must set qconnectstatedir — if it hasn't, this
    // returns empty and main() aborts with that instruction (no invented path).
    if (const char* xdg = std::getenv("XDG_STATE_HOME"); xdg && *xdg)
        return std::string(xdg) + "/qobuzconnect2mpd";
    if (const char* home = std::getenv("HOME"); home && *home)
        return std::string(home) + "/.local/state/qobuzconnect2mpd";
    return {};
}

// ---- Entry point ------------------------------------------------------------

int main(int argc, char* argv[]) {
    std::string config_file = "/etc/upmpdcli.conf";
    std::string status_file_arg;
    bool daemonise = false;
    bool login_only = false;
    int verbosity = 0;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            config_file = argv[++i];
        } else if (!strcmp(argv[i], "-d")) {
            daemonise = true;
        } else if (!strcmp(argv[i], "-L")) {
            login_only = true;
        } else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
            status_file_arg = argv[++i];
        } else if (argv[i][0] == '-' && argv[i][1] == 'v' &&
                   argv[i][2] != '\0' &&
                   strspn(argv[i] + 1, "v") == strlen(argv[i] + 1)) {
            verbosity += static_cast<int>(strlen(argv[i] + 1));
        } else if (!strcmp(argv[i], "-v")) {
            ++verbosity;
        } else if (!strcmp(argv[i], "--debug")) {
            if (verbosity < 1) verbosity = 1;
        } else if (!strcmp(argv[i], "--trace")) {
            if (verbosity < 2) verbosity = 2;
        } else {
            std::cerr << "Usage: " << argv[0]
                      << " [-c configfile] [-d] [-L] [-o statusfile] [-v|-vv]\n";
            return 1;
        }
    }

    // -L is an interactive bootstrap: never fork away from the terminal.
    if (daemonise && !login_only) {
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
        if (value == "3" || value == "trace" || value == "trc")
            return QC_LOG_TRACE;
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
    if (verbosity >= 2)
        g_qc_log_level = QC_LOG_TRACE;
    else if (verbosity == 1)
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

    // mDNS is required for LAN discovery unless the operator runs cloud-only.
    qcfg.mdns_required = cfgGetBool(cfg, "qconnectmdnsrequired", true);

    // Runtime mode: a TTY lets a missing token be resolved via browser OAuth in
    // place; a headless service must have a cached token (bootstrap with -L).
    qcfg.login_only  = login_only;
    qcfg.interactive = login_only ||
                       ::isatty(STDIN_FILENO) || ::isatty(STDOUT_FILENO);

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

    // Single state directory: holds the OAuth token and the device UUID.
    // Created if missing so a fresh install works without manual setup.
    std::string state_dir = resolveStateDir(cfg);
    if (state_dir.empty()) {
        std::cerr << "qobuzconnect2mpd: cannot determine a state directory; "
                     "set qconnectstatedir in the config\n";
        return 1;
    }
    if (!makeDirs(state_dir, 0700)) {
        std::cerr << "qobuzconnect2mpd: cannot create state directory "
                  << state_dir << ": " << strerror(errno) << "\n";
        return 1;
    }
    qcfg.state_dir = state_dir;
    LOGSTD("qobuzconnect2mpd: state dir: " << state_dir << "\n");

    // UUID persists across restarts so the device keeps a stable identity in
    // the Qobuz app (otherwise every restart appears as a new device).
    std::string uuid_path = state_dir + "/device.uuid";
    {
        std::ifstream sf(uuid_path);
        if (sf) std::getline(sf, qcfg.uuid);
    }
    // QcManager generates a UUID if empty; it is saved after start().

    // ---- Start manager -----------------------------------------------------
    QcManager mgr(qcfg);

    if (!mgr.start()) {
        std::cerr << "qobuzconnect2mpd: startup failed\n";
        return 1;
    }

    LOGINF("qobuzconnect2mpd: started, UUID=" << mgr.uuid() << "\n");

    // Persist UUID to state file (may have been generated by QcManager)
    {
        std::ofstream sf(uuid_path);
        if (sf) sf << mgr.uuid() << "\n";
    }

    // -L bootstrap: wait for the browser login to complete, cache the token,
    // then exit so the operator can start the service normally.
    if (login_only) {
        LOGSTD("qobuzconnect2mpd: -L bootstrap — waiting for browser login "
               "(up to 5 minutes)...\n");
        int waited = 0;
        while (!g_quit && !mgr.authenticated() && waited < 300) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            ++waited;
        }
        int rc = 0;
        if (mgr.authenticated()) {
            LOGSTD("qobuzconnect2mpd: authenticated — token cached in "
                   << state_dir << ". You can now start the service.\n");
        } else {
            std::cerr << "qobuzconnect2mpd: login not completed within the "
                         "timeout; token not cached\n";
            rc = 1;
        }
        mgr.stop();
        return rc;
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
