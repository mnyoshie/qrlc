#ifndef QUTILS_H
#define QUTILS_H

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "include/config.h"
#include "include/types.h"
#include "log.h"

#if defined(QHAVE_BSWAP)
#  include <byteswap.h>

#  define QBSWAP64(x) bswap_64(x)
#  define QBSWAP32(x) bswap_32(x)
#  define QBSWAP16(x) bswap_16(x

#elif defined(_MSVC_VER)
#  define QBSWAP64(x) _byteswap_uint64(x)
#  define QBSWAP32(x) _byteswap_ulong(x)
#  define QBSWAP16(x) _byteswap_short(x)

#else
#  define QBSWAP64(x) qbswap_64(x)
#  define QBSWAP32(x) qbswap_32(x)
#  define QBSWAP16(x) qbswap_16(x)

static inline uint16_t qbswap_16(uint16_t n) {
  return ((n & 0xff00) >> 8) | ((n & 0xff) << 8);
}

static inline uint32_t qbswap_32(uint32_t n) {
  uint32_t a = (n & (uint32_t)0xff000000) >> (3 * 8);
  uint32_t b = (n & (uint32_t)0x00ff0000) >> (1 * 8);
  uint32_t c = (n & (uint32_t)0x0000ff00) << (1 * 8);
  uint32_t d = (n & (uint32_t)0x000000ff) << (3 * 8);
  return a | b | c | d;
}
static inline uint64_t qbswap_64(uint64_t n) {
  uint64_t a = (n & (uint64_t)0xff00000000000000) >> (7 * 8);
  uint64_t b = (n & (uint64_t)0x00ff000000000000) >> (5 * 8);
  uint64_t c = (n & (uint64_t)0x0000ff0000000000) >> (3 * 8);
  uint64_t d = (n & (uint64_t)0x000000ff00000000) >> (1 * 8);
  uint64_t e = (n & (uint64_t)0x00000000ff000000) << (1 * 8);
  uint64_t f = (n & (uint64_t)0x0000000000ff0000) << (3 * 8);
  uint64_t g = (n & (uint64_t)0x000000000000ff00) << (5 * 8);
  uint64_t h = (n & (uint64_t)0x00000000000000ff) << (7 * 8);
  return a | b | c | d | e | f | g | h;
}
#endif

#if defined(QLITTLE_ENDIAN)

#  define QINT2BIG_64(x) QBSWAP64(x)
#  define QINT2BIG_32(x) QBSWAP32(x)
#  define QINT2BIG_16(x) QBSWAP16(x)

#  define QINT2LIT_64(x) x
#  define QINT2LIT_32(x) x
#  define QINT2LIT_16(x) x


#elif defined(QBIG_ENDIAN)

#  define QINT2LIT_64(x) QBSWAP64(x)
#  define QINT2LIT_32(x) QBSWAP32(x)
#  define QINT2LIT_16(x) QBSWAP16(x)

#  define QINT2BIG_64(x) x
#  define QINT2BIG_32(x) x
#  define QINT2BIG_16(x) x

#else
#  error "unknown machine endian"
#endif /* QRL_MACHINE_*_ENDIAN */

#if SIZE_MAX == 0xffffffff /* sizeof(size_t) == 4 */
#  define QINT2LIT_SIZET(x) QINT2LIT_32(x)
#  define QINT2BIG_SIZET(x) QINT2BIG_32(x)
#elif SIZE_MAX == 0xffffffffffffffff /* sizeof(size_t) == 8 */
#  define QINT2LIT_SIZET(x) QINT2LIT_64(x)
#  define QINT2BIG_SIZET(x) QINT2BIG_64(x)
#else
#  error "unsupported sizeof(size_t) size"
#endif

#ifdef __has_builtin
#  if __has_builtin(__builtin_add_overflow) && \
      __has_builtin(__builtin_sub_overflow)
#    define QBUILTIN_ADDU64(a, b, res) __builtin_add_overflow(a, b, res)
#    define QBUILTIN_ADDSIZET(a, b, res) __builtin_add_overflow(a, b, res)
#    define QBUILTIN_SUBU64(a, b, res) __builtin_sub_overflow(a, b, res)
#  endif
#endif

#ifndef QRL_BUILTIN_ADDU64
// static int qrl_builtin_addu64(uint64_t a, uint64_t b, uint64_t *res) {
//   if (a > (~(uint64_t)0) - b) {
//     *res = ~((uint64_t)0);
//     return 1;
//   }
//   *res = a + b;
//   return 0;
// }
//
///* I know what you're thinking. unsigned types wrap around when overflowed
// * so why the need?
// */
// static int qrl_builtin_addsizet(size_t a, size_t b, size_t *res) {
//  if (a > (~(size_t)0) - b) {
//    *res = ~((size_t)0);
//    return 1;
//  }
//  *res = a + b;
//  return 0;
//}
//
// static int qrl_builtin_subu64(uint64_t a, uint64_t b, uint64_t *res) {
//  if (a < b) {
//    *res = 0;
//    return 1;
//  }
//  *res = a - b;
//  return 0;
//}

#  define QRL_BUILTIN_ADDU64(a, b, res) qrl_builtin_addu64(a, b, res)
#  define QRL_BUILTIN_ADDSIZET(a, b, res) qrl_builtin_addsizet(a, b, res)
#  define QRL_BUILTIN_SUBU64(a, b, res) qrl_builtin_subu64(a, b, res)
#endif /* __has_builtin */

// static int qrl_addsizet(size_t *res, int count, ...) {
//   va_list ap;
//   va_start(ap, count);
//
//   size_t sum = 0;
//   for (int i = 0; i < count; i++) {
//     size_t v = va_arg(ap, size_t);
//     if (QRL_BUILTIN_ADDSIZET(sum, v, &sum)) {
//       va_end(ap);
//       /* overflowed */
//       return 1;
//     }
//   }
//
//   va_end(ap);
//   *res = sum;
//   return 0;
// }

struct inctr_t {
  size_t i;
};

static inline size_t pincrement(struct inctr_t *t, size_t s) {
  return t->i += s;
}

static inline size_t incrementp(struct inctr_t *t, size_t s) {
  size_t i = t->i;
  t->i += s;
  return i;
}

extern void qrl_dump_ex(int type, char *data, size_t len);
extern void qrl_dump(void *data, size_t len);
extern void qrl_printx(void *data, size_t len);
// extern void *qrl_alloc_secure_page(void);

#endif /* QUTILS_H */
