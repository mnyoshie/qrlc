#ifndef QRL_UTILS_H
#define QRL_UTILS_H

#include <stdlib.h>
#include <limits.h>
#include <assert.h>
#include <byteswap.h>
#include <arpa/inet.h>

#include "log.h"

#include "include/config.h"

#define QBSWAP64(x) bswap_64(x)
#define QBSWAP32(x) bswap_32(x)
#define QBSWAP16(x) bswap_16(x)

#if defined(QRL_MACHINE_LITTLE_ENDIAN)
#define QLITTLE2BIG32(x) QBSWAP32(x)
#endif

#if defined(QRL_MACHINE_BIG_ENDIAN)
#define QBIG2LITTLE32(x) QBSWAP32(x)
#endif

#ifdef __has_builtin
#  if __has_builtin(__builtin_add_overflow) && __has_builtin(__builtin_sub_overflow)
#    define QBUILTIN_ADDU64(a, b, res) __builtin_add_overflow(a, b, res)
#    define QBUILTIN_ADDSIZET(a, b, res) __builtin_add_overflow(a, b, res)
#    define QBUILTIN_SUBU64(a, b, res) __builtin_sub_overflow(a, b, res)
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

extern void qrl_dump_ex(int type, char *data, size_t len);
extern void qrl_dump(void *data, size_t len);
extern void qrl_printx(void *data, size_t len);
extern void *qrl_alloc_secure_page(void);
//extern void qrl_free_secure_page(void *mem);

#endif /* QRL_ULTILS_H */
