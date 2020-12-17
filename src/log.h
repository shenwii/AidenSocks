#ifndef _LOG_H
#define _LOG_H

#include "msg.h"
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#define LOG_INFO(fmt, ...)                           \
    {                                                \
        struct timeval __time;                       \
        gettimeofday(&__time, NULL);                 \
        struct tm *__tm;                             \
        __tm = localtime(&__time.tv_sec);            \
        fprintf(stdout, "INFO:    ");                \
        fprintf(stdout,                              \
            "%04d/%02d/%02d %02d:%02d:%02d.%06ld, " ,\
            __tm->tm_year + 1900,                    \
            __tm->tm_mon + 1,                        \
            __tm->tm_mday,                           \
            __tm->tm_hour,                           \
            __tm->tm_min,                            \
            __tm->tm_sec,                            \
            __time.tv_usec                           \
        );                                           \
        fprintf(stdout, fmt, ## __VA_ARGS__);        \
        fflush(stdout);                              \
    }

#define LOG_ERR(fmt, ...)                            \
    {                                                \
        struct timeval __time;                       \
        gettimeofday(&__time, NULL);                 \
        struct tm *__tm;                             \
        __tm = localtime(&__time.tv_sec);            \
        fprintf(stderr, "ERROR:   ");                \
        fprintf(stderr,                              \
            "%04d/%02d/%02d %02d:%02d:%02d.%06ld, " ,\
            __tm->tm_year + 1900,                    \
            __tm->tm_mon + 1,                        \
            __tm->tm_mday,                           \
            __tm->tm_hour,                           \
            __tm->tm_min,                            \
            __tm->tm_sec,                            \
            __time.tv_usec                           \
        );                                           \
        fprintf(stderr, fmt, ## __VA_ARGS__);        \
        fflush(stderr);                              \
    }

#define LOG_WARN(fmt, ...)                           \
    {                                                \
        struct timeval __time;                       \
        gettimeofday(&__time, NULL);                 \
        struct tm *__tm;                             \
        __tm = localtime(&__time.tv_sec);            \
        fprintf(stdout, "WARNING: ");                \
        fprintf(stdout,                              \
            "%04d/%02d/%02d %02d:%02d:%02d.%06ld, " ,\
            __tm->tm_year + 1900,                    \
            __tm->tm_mon + 1,                        \
            __tm->tm_mday,                           \
            __tm->tm_hour,                           \
            __tm->tm_min,                            \
            __tm->tm_sec,                            \
            __time.tv_usec                           \
        );                                           \
        fprintf(stdout, fmt, ## __VA_ARGS__);        \
        fflush(stdout);                              \
    }

#ifdef DEBUG
# define LOG_DEBUG(fmt, ...)                         \
    {                                                \
        struct timeval __time;                       \
        gettimeofday(&__time, NULL);                 \
        struct tm *__tm;                             \
        __tm = localtime(&__time.tv_sec);            \
        fprintf(stderr, "DEBUG:   ");                \
        fprintf(stderr,                              \
            "%04d/%02d/%02d %02d:%02d:%02d.%06ld, " ,\
            __tm->tm_year + 1900,                    \
            __tm->tm_mon + 1,                        \
            __tm->tm_mday,                           \
            __tm->tm_hour,                           \
            __tm->tm_min,                            \
            __tm->tm_sec,                            \
            __time.tv_usec                           \
        );                                           \
        fprintf(stderr, fmt, ## __VA_ARGS__);        \
        fflush(stderr);                              \
    }
#else
# define LOG_DEBUG(fmt, ...)
#endif

#endif
