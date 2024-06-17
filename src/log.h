#ifndef QLOG_H
#define QLOG_H

#define QLOG_INFO     (1)

#define QLOG_WARNING  (1<<1)

#define QLOG_ERROR    (1<<2)

#define QLOG_VERBOSE  (1<<3)

#define QLOG_DEBUG    (1<<4)

#define QLOG_TRACE    (1<<5)

#define QLOG_PANIC    (1<<6)

#define QLOGX(type, ...) qrl_log_ex(type, __FILE__, __func__, __LINE__, __VA_ARGS__)

#define QLOG(...) QLOG_EX(QLOG_INFO, __VA_ARGS__)

void qrl_log_ex(int type, char *file, const char *func, int line, const char *format, ...);

extern int qrl_log_level; 
#endif /* QLOG_H */
