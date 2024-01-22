#ifndef QRL_UTILS_H
#define QRL_UTILS_H

#include "config.h"
#include <byteswap.h>
#include <limits.h>

#if QRL_MACHINE_BIG_ENDIAN == 1
#define QRL_BSWAP64(x) (x)
#define QRL_BSWAP32(x) (x)
#define QRL_BSWAP16(x) (x)
#elif QRL_MACHINE_LITTLE_ENDIAN == 1
#define QRL_BSWAP64(x) bswap_64(x)
#define QRL_BSWAP32(x) bswap_32(x)
#define QRL_BSWAP16(x) bswap_16(x)
#else
#error "unknown machine endian!"
#endif

#ifdef __has_builtin
#  if __has_builtin(__builtin_add_overflow) && __has_builtin(__builtin_sub_overflow)
#    define QRL_BUILTIN_ADDU64(a, b, res) __builtin_add_overflow(a, b, res)
#    define QRL_BUILTIN_ADDSIZET(a, b, res) __builtin_add_overflow(a, b, res)
#    define QRL_BUILTIN_SUBU64(a, b, res) __builtin_sub_overflow(a, b, res)
#  endif
#endif

#ifndef QRL_BUILTIN_ADDU64
static int qrl_builtin_addu64(uint64_t a, uint64_t b, uint64_t *res) {
  if (a > (~(uint64_t)0) - b) {
    *res = ~((uint64_t)0);
    return 1;
  }
  *res = a + b;
  return 0;
}

/* I know what you're thinking. unsigned types wrap around when overflowed
 * so why the need?
 */
static int qrl_builtin_addsizet(size_t a, size_t b, size_t *res) {
  if (a > (~(size_t)0) - b) {
    *res = ~((size_t)0);
    return 1;
  }
  *res = a + b;
  return 0;
}

static int qrl_builtin_subu64(uint64_t a, uint64_t b, uint64_t *res) {
  if (a < b) {
    *res = 0;
    return 1;
  }
  *res = a - b;
  return 0;
}

#define QRL_BUILTIN_ADDU64(a, b, res) qrl_builtin_addu64(a, b, res)
#define QRL_BUILTIN_ADDSIZET(a, b, res) qrl_builtin_addsizet(a, b, res)
#define QRL_BUILTIN_SUBU64(a, b, res) qrl_builtin_subu64(a, b, res)
#endif /* __has_builtin */

static int qrl_addsizet(size_t *res, int count, ...) { 
  va_list ap;
  va_start (ap, count);

  size_t sum = 0;
  for (int i = 0; i < count; i++) {
    size_t v = va_arg (ap, size_t);
    if (QRL_BUILTIN_ADDSIZET(sum, v, &sum)) {
      va_end(ap);
      /* overflowed */
      return 1;
    }
  }

  va_end(ap);
  *res = sum;
  return 0;
}

#ifdef QRL_UTILS_DECLARE
#define QRL_UTILS_EXTERN
#else
#define QRL_UTILS_EXTERN extern
#endif

QRL_UTILS_EXTERN void qrl_dump_ex(int type, void *data, size_t len);
QRL_UTILS_EXTERN void qrl_dump(void *data, size_t len);
QRL_UTILS_EXTERN void qrl_printx(void *data, size_t len);

QRL_UTILS_EXTERN void *qrl_alloc_secure_page(void);
QRL_UTILS_EXTERN void qrl_free_secure_page(void *mem);

#endif /* QRL_ULTILS_H */
