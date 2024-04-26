#define QRL_LOG_DECLARE
#include "log.h"
#include "include/ansicolors.h"

void qrl_log_ex(int type, char *file, const char *func, int line,
                const char *format, ...) {
  if (!(type & qrl_log_level)) return;

  va_list argptr;
  va_start(argptr, format);
  switch (type) {
    case QRL_LOG_PANIC:
      fprintf(stderr, "[" COLSTR("PANIC", BHRED) " %s:%d @ %s] ", file, line,
              func);
      vfprintf(stderr, format, argptr);
      break;
    case QRL_LOG_INFO:
      fprintf(stdout, "[%s @ %s:%d] ", func, file, line);
      vfprintf(stdout, format, argptr);
      fflush(stdout);
      break;
    case QRL_LOG_WARNING:
      fprintf(stderr, "[" COLSTR("warning %s @ %s:%d", BHYEL) "] ", func,
              file, line);
      vfprintf(stderr, format, argptr);
      break;
    case QRL_LOG_ERROR:
      fprintf(stderr, "[" COLSTR("error %s @ %s:%d", BRED) "] ", func, file,
              line);
      vfprintf(stderr, format, argptr);
      break;
    case QRL_LOG_VERBOSE:
      fprintf(stderr, "[" COLSTR("%s @ %s:%d", BHMAG) "] ", func, file,
              line);
      vfprintf(stderr, format, argptr);
      break;
    case QRL_LOG_DEBUG:
      fprintf(stderr, "[debug %s @ %s:%d] ", func, file, line);
      vfprintf(stderr, format, argptr);
      break;
    case QRL_LOG_TRACE:
      fprintf(stderr, "[TRACE %s @ %s:%d] ", func, file, line);
      vfprintf(stderr, format, argptr);
      break;
    default:;
  }
  va_end(argptr);
  return;
}
