#define QRL_LOG_DECLARE
#include "include/log.h"

#ifdef __unix__
#  define RED_ON "\x1b[1;31m"
#  define GREEN_ON "\x1b[1;32m"
#  define YELLOW_ON "\x1b[1;33m"
#  define BLUE_ON "\x1b[1;34m"
#  define MAGENTA_ON "\x1b[1;35m"
#  define COLOR_OFF "\x1b[0m"
#else
#  define GREEN_ON
#  define RED_ON
#  define COLOR_OFF
#endif

void qrl_log_ex(int type, char *file, const char *func, int line,
                const char *format, ...) {
  if (!(type & qrl_log_level)) return;

  va_list argptr;
  va_start(argptr, format);
  switch (type) {
    case QRL_LOG_PANIC:
      fprintf(stderr, "[" RED_ON "PANIC" COLOR_OFF " %s:%d @ %s] ", file, line,
              func);
      vfprintf(stderr, format, argptr);
      break;
    case QRL_LOG_INFO:
      fprintf(stdout, "[%s @ %s:%d] ", func, file, line);
      vfprintf(stdout, format, argptr);
      fflush(stdout);
      break;
    case QRL_LOG_WARNING:
      fprintf(stderr, "[" YELLOW_ON "warning %s @ %s:%d" COLOR_OFF "] ", func,
              file, line);
      vfprintf(stderr, format, argptr);
      break;
    case QRL_LOG_ERROR:
      fprintf(stderr, "[" RED_ON "error %s @ %s:%d" COLOR_OFF "] ", func, file,
              line);
      vfprintf(stderr, format, argptr);
      break;
    case QRL_LOG_VERBOSE:
      fprintf(stderr, "[" MAGENTA_ON "%s @ %s:%d" COLOR_OFF "] ", func, file,
              line);
      vfprintf(stderr, format, argptr);
      break;
    case QRL_LOG_DEBUG:
      fprintf(stderr, "[debug %s @ %s:%d] ", func, file, line);
      vfprintf(stderr, format, argptr);
      break;
    case QRL_LOG_TRACE:
      /* BLUE SCREEN OF DEATH. */
      fprintf(stderr, BLUE_ON);
      fprintf(stderr, "[TRACE %s @ %s:%d] ", func, file, line);
      vfprintf(stderr, format, argptr);
      fprintf(stderr, COLOR_OFF);
      break;
  }
  va_end(argptr);
  return;
}
