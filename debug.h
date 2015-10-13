#ifndef HTTP_DEBUG_H
#define HTTP_DEBUG_H

#include <stdio.h>

#ifdef NDEBUG

#define dbg_warn(msg) do {;} while (0)
#define dbg_warnf(msg, ...) do {;} while (0)

#else

#define dbg_warn(msg) fprintf(stderr, "%s: %s\n", __func__, (msg))
#define dbg_warnf(msg, ...) fprintf(stderr, "%s:" msg "\n", __func__, __VA_ARGS__)

#endif

#endif
