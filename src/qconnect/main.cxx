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
//   # Qobuz credentials — reused from qobuz plugin if not set here:
//   qconnectuser           Qobuz username  (falls back to qobuzuser)
//   qconnectpass           Qobuz password  (falls back to qobuzpass)
//   qconnectappid          App ID          (falls back to qobuzappid)
//   qconnectcfvalue        App secret      (falls back to qobuzcfvalue)
//
//   # MPD connection (reused from main upmpdcli config):
//   mpdhost / mpdport / mpdpassword
//
// Usage:
//   qconnect2mpd [-c configfile] [-d]
//     -c  path to upmpdcli config file
//     -d  daemonise (fork to background)

#include "qcmgr.hxx"
#include "qclog.hxx"

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <unistd.h>

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
    bool daemonise = false;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            config_file = argv[++i];
        } else if (!strcmp(argv[i], "-d")) {
            daemonise = true;
        } else {
            std::cerr << "Usage: " << argv[0] << " [-c configfile] [-d]\n";
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
    if (!cfg.ok()) {
        std::cerr << "qconnect2mpd: cannot read config " << config_file << "\n";
        // Non-fatal: use defaults
    }

    using namespace QConnect;

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

    // Qobuz credentials — prefer qconnect-specific, fall back to qobuz plugin
    qcfg.qobuz_user   = cfgGet(cfg, "qconnectuser",
                                 cfgGet(cfg, "qobuzuser"));
    qcfg.qobuz_pass   = cfgGet(cfg, "qconnectpass",
                                 cfgGet(cfg, "qobuzpass"));
    qcfg.app_id       = cfgGet(cfg, "qconnectappid",
                                 cfgGet(cfg, "qobuzappid"));
    qcfg.app_secret   = cfgGet(cfg, "qconnectcfvalue",
                                 cfgGet(cfg, "qobuzcfvalue"));

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
    while (!g_quit) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    LOGINF("qconnect2mpd: shutting down\n");
    mgr.stop();
    return 0;
}
