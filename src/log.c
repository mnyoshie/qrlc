#include <stdio.h>
#include <stdarg.h>

#include "log.h"
#include "include/ansicolors.h"

int qrl_log_level = ~0 & ~QLOG_TRACE;
void qrl_log_ex(int type, char *file, const char *func, int line,
                const char *format, ...) {
  if (!(type & qrl_log_level)) return;

  va_list argptr;
  va_start(argptr, format);
  switch (type) {
    case QLOG_PANIC:
      fprintf(stderr, "[" COLSTR("PANIC", BHRED) " %s:%d @ %s] ", file, line,
              func);
      vfprintf(stderr, format, argptr);
      break;
    case QLOG_INFO:
      fprintf(stdout, "[%s @ %s:%d] ", func, file, line);
      vfprintf(stdout, format, argptr);
      fflush(stdout);
      break;
    case QLOG_WARNING:
      fprintf(stderr, "[" COLSTR("warning %s @ %s:%d", BHYEL) "] ", func,
              file, line);
      vfprintf(stderr, format, argptr);
      break;
    case QLOG_ERROR:
      fprintf(stderr, "[" COLSTR("error %s @ %s:%d", BRED) "] ", func, file,
              line);
      vfprintf(stderr, format, argptr);
      break;
    case QLOG_VERBOSE:
      fprintf(stderr, "[" COLSTR("%s @ %s:%d", BHMAG) "] ", func, file,
              line);
      vfprintf(stderr, format, argptr);
      break;
    case QLOG_DEBUG:
      fprintf(stderr, "[debug %s @ %s:%d] ", func, file, line);
      vfprintf(stderr, format, argptr);
      break;
    case QLOG_TRACE:
      fprintf(stderr, "[TRACE %s @ %s:%d] ", func, file, line);
      vfprintf(stderr, format, argptr);
      break;
    default:;
  }
  va_end(argptr);
  return;
}
