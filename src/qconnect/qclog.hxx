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

// Lightweight logging for the qconnect2mpd standalone daemon.
// Falls back to stderr if libupnpp log is not available.
// Usage: LOGDEB("message " << var << "\n")

#ifdef MDU_INCLUDE_LOG
#  include MDU_INCLUDE_LOG
#else
#  include <cstdlib>
#  include <ctime>
#  include <fstream>
#  include <iostream>
#  include <mutex>
#  include <sstream>
#  include <string>

// Global log file — defined in main.cxx, opened there if qconnectlogfile is set.
extern std::ofstream g_qc_log_file;
// Serialises writes from multiple threads (MPD event, background materializer, etc.)
extern std::mutex    g_qc_log_mutex;

// Verbosity level, defined in main.cxx (default QC_LOG_ERROR). Higher levels
// include all lower ones. Set from the qconnectloglevel config key / QC_DEBUG
// or QC_LOGLEVEL environment variables.
//   0 = errors only (LOGERR)         — the default, minimal output
//   1 = + info/normal (LOGINF/LOGSTD)
//   2 = + debug trace (LOGDEB)
extern int g_qc_log_level;

namespace QConnect {
enum { QC_LOG_ERROR = 0, QC_LOG_INFO = 1, QC_LOG_DEBUG = 2 };

inline std::string qcTimestamp() {
    time_t t = time(nullptr);
    char buf[20];
    struct tm* tm_info = localtime(&t);
    if (tm_info) strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    else          buf[0] = '\0';
    return buf;
}
} // namespace QConnect

// LOGERR — stderr + log file (errors)
#  ifndef LOGERR
#    define LOGERR(X) do { \
         std::ostringstream _s; _s << X; \
         std::lock_guard<std::mutex> _lk(g_qc_log_mutex); \
         std::cerr << "[ERR] " << _s.str(); \
         if (g_qc_log_file.is_open()) \
             g_qc_log_file << QConnect::qcTimestamp() << " [ERR] " << _s.str() << std::flush; \
     } while(0)
#  endif

// LOGINF — log file only, silent on terminal (informational events).
// Emitted at log level >= QC_LOG_INFO (1).
#  ifndef LOGINF
#    define LOGINF(X) do { \
         if (g_qc_log_level >= QConnect::QC_LOG_INFO && g_qc_log_file.is_open()) { \
             std::ostringstream _s; _s << X; \
             std::lock_guard<std::mutex> _lk(g_qc_log_mutex); \
             g_qc_log_file << QConnect::qcTimestamp() << " [INF] " << _s.str() << std::flush; \
         } \
     } while(0)
#  endif

// LOGSTD — stdout + log file (normal operational output shown to the user)
#  ifndef LOGSTD
#    define LOGSTD(X) do { \
         std::ostringstream _s; _s << X; \
         std::lock_guard<std::mutex> _lk(g_qc_log_mutex); \
         std::cout << _s.str(); \
         if (g_qc_log_file.is_open()) \
             g_qc_log_file << QConnect::qcTimestamp() << " [OUT] " << _s.str() << std::flush; \
     } while(0)
#  endif

// LOGDEB — log file only, emitted at log level >= QC_LOG_DEBUG (2).
#  ifndef LOGDEB
#    define LOGDEB(X) do { \
         if (g_qc_log_level >= QConnect::QC_LOG_DEBUG && g_qc_log_file.is_open()) { \
             std::ostringstream _s; _s << X; \
             std::lock_guard<std::mutex> _lk(g_qc_log_mutex); \
             g_qc_log_file << QConnect::qcTimestamp() << " [DEB] " << _s.str() << std::flush; \
         } \
     } while(0)
#  endif
#endif
