#include <stdio.h>
#include "utils.h"
#include "inttypes.h"

static void dump_decode_binary(const char *const data, const size_t len) {
  int space_padding = 50;
  char look_up[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  for (size_t i = 0; i < len; i++) {
    putchar(look_up[(data[i] >> 4) & 0x0f]);
    putchar(look_up[data[i] & 0x0f]);
    putchar(' ');
    space_padding -= 3;
    if (i == 7) {putchar(' '); space_padding--;}
  }
  for (int i = 0; i < space_padding; i++)
    putchar(' ');
}

static void dump_decode_ascii(const char *const data, const size_t len) {
  int space_padding = 16;
  printf("|");
  for (size_t i = 0; i < len; i++) {
    space_padding--;
    if (data[i] < 0x20) {
      putchar('.');
    } else if (data[i] < 0x7f)
      putchar(data[i]);
    else
      putchar('.');
  }
  for (int i = 0; i < space_padding; i++)
    putchar(' ');
  printf("|");
}

void qrl_dump_ex(const int unused, const char *const data, const size_t len) {
//  if (len == 0) return;
//  if (!(type & qrl_log_level)) return;
  size_t to_write = 16;

  for (const char *cur = data; cur != data + len; cur += to_write) {
    /* make sure we don't overflow */
    if ((size_t)(cur + to_write) > (size_t)(data + len))
      to_write = (size_t)((data + len) - cur);

    assert(cur >= data);
    printf("%08"PRIx32"  ", (uint32_t)(cur - data));
    dump_decode_binary(cur, to_write);
    dump_decode_ascii(cur, to_write);
    puts("");
  }
//  assert(len == (size_t)(idata - data));
}

void qrl_dump(const void *data, const size_t len) {qrl_dump_ex(QLOG_INFO, data, len); }

void qrl_printx(void *data, size_t len) {
  char *c = data;
  for (size_t i = 0; i < len; i++) printf("%02x", (qu8)c[i]);
  puts("");
}

char *qrl_sprintx(void *data, size_t len) {
  char *c = data;
  char *buf = calloc(1, len*2 + 3);
  assert(buf != NULL);
  size_t i;
  for (i = 0; i < len; i++) snprintf(buf + i*2, 2, "%02x", (qu8)c[i]);

  buf[i] = '\n';
  return buf;
}

// #ifdef MAP_NOCORE
// #  define QRL_MAP_NOCORE MAP_NOCORE
// #else
// #  define QRL_MAP_NOCORE 0
// #endif
//
// #ifdef MAP_CONCEAL
// #  define QRL_MAP_CONCEAL MAP_CONCEAL
// #else
// #  define QRL_MAP_CONCEAL 0
// #endif
//
///* special function for allocating sensitive memory for private keys */
///* MUST ONLY BE FREED by qrl_free_secure_page()
// */
// void *qrl_alloc_secure_page() {
//  void *mem = mmap(
//      NULL, getpagesize(), PROT_WRITE,
//      MAP_PRIVATE | MAP_ANONYMOUS | QRL_MAP_NOCORE | QRL_MAP_CONCEAL, -1, 0);
//  if (mem == MAP_FAILED) {
//    QLOGX(QLOG_ERROR, "mmap()");
//    perror("");
//    return NULL;
//  }
//
//  /* lock secure page */
//  if (mlock(mem, getpagesize())) {
//    QLOGX(QLOG_ERROR, "failed to lock memory %p\n", mem);
//    munmap(mem, getpagesize());
//    return NULL;
//  }
//
//  return mem;
//}
//
// void qrl_free_secure_page(void *mem) {
//  if (mem == NULL) return;
//  memset(mem, 0xaa, getpagesize());
//  memset(mem, 0x55, getpagesize());
//  memset(mem, 0x0f, getpagesize());
//  memset(mem, 0xf0, getpagesize());
//  memset(mem, 0x00, getpagesize());
//
//  if (munlock(mem, getpagesize())) {
//    QLOGX(QLOG_WARNING, "failed to unlock memory %p\n", mem);
//  }
//
//  munmap(mem, getpagesize());
//  QLOGX(QLOG_TRACE, "freed %d bytes on %p\n", getpagesize(), mem);
//}
//
// void *qrl_qalloc(size_t s) {
//  void *mem = malloc(s);
//  if (mem == NULL) {
//    QLOGX(QLOG_WARNING, "couldn't allocated %d bytes\n", s);
//    return NULL;
//  }
//  return mem;
//}
//
// void *qrl_calloc(size_t n, size_t s) {
//  void *mem = calloc(n, s);
//  if (mem == NULL) {
//    QLOGX(QLOG_WARNING, "couldn't allocated %d bytes\n", n * s);
//    return NULL;
//  }
//  return mem;
//}
//
// void qrl_free(void *mem) {
//  if (mem == NULL) return;
//  free(mem);
//}
