#ifndef QRL_LOG_H
#define QRL_LOG_H

#include <stdio.h>
#include <stdarg.h>


#define QRL_LOG_INFO     (1)

#define QRL_LOG_WARNING  (1<<1)

#define QRL_LOG_ERROR    (1<<2)

#define QRL_LOG_VERBOSE  (1<<3)

#define QRL_LOG_DEBUG    (1<<4)

#define QRL_LOG_TRACE    (1<<5)

#define QRL_LOG_PANIC    (1<<6)

/* Logging with extra fancy features. The ## is non standard.
 * If it produces errors, maybe turn QRL_LOG_EX and QRL_LOG into
 * a real function and put random valid values to __FILE__, __func__, __LINE__.
 * */
#define QRL_LOG_EX(type, fmt, ...) qrl_log_ex(type, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)

#define QRL_LOG(msg, ...) QRL_LOG_EX(QRL_LOG_INFO, msg, ##__VA_ARGS__)


#ifdef QRL_LOG_DECLARE
#define QRL_LOG_EXTERN
#else
#define QRL_LOG_EXTERN extern
#endif

QRL_LOG_EXTERN void qrl_log_ex(int type, char *file, const char *func, int line, const char *format, ...);

QRL_LOG_EXTERN int qrl_log_level; 
#endif /* QRL_LOG_H */
