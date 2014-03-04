#include "log.h"

void gjoll_flog(FILE *f, const char *format, ...) {
    GJOLL_LOG(f, format);
}

void gjoll_log(const char *format, ...) {
    GJOLL_LOG(stdout, format);
}

void gjoll_logerr(const char *format, ...) {
    GJOLL_LOG(stderr, format);
}
