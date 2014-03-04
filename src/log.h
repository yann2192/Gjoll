#ifndef GJOLL_LOG_H
#define GJOLL_LOG_H

#include <stdio.h>
#include <stdarg.h>

#define GJOLL_LOG(f, format) do {\
    va_list ap;\
    va_start(ap, format);\
    vfprintf(f, format, ap);\
    va_end(ap);\
}while(0);

void gjoll_flog(FILE *f, const char *format, ...);

void gjoll_log(const char *format, ...);

void gjoll_logerr(const char *format, ...);

#endif
