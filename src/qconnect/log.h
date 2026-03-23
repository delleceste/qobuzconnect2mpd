// Stub log.h for qconnect2mpd standalone build.
// conftree.cpp includes "log.h"; this maps it to our stderr-based macros.
#pragma once
#include "qclog.hxx"

// conftree.cpp uses LOGDEB0 and LOGDEB2 in addition to LOGDEB/LOGERR.
#ifndef LOGDEB0
#  define LOGDEB0 LOGDEB
#endif
#ifndef LOGDEB1
#  define LOGDEB1 LOGDEB
#endif
#ifndef LOGDEB2
#  define LOGDEB2 LOGDEB
#endif
