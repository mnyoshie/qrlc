#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "include/log.h"

static void qrl_dump_decode_binary(char *data, int len) {
  char look_up[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  for (int i = 0; i < len; i++) {
    putchar(look_up[(data[i] >> 4) & 0x0f]);
    putchar(look_up[data[i] & 0x0f]);
    putchar(' ');
    if (i == 7) putchar(' ');
  }
}

static void qrl_dump_decode_ascii(char *data, int len) {
  for (int i = 0; i < len; i++) {
    if (data[i] < 0x20) {
      putchar('.');
    } else if (data[i] < 0x7f)
      putchar(data[i]);
    else
      putchar('.');
  }
}

void qrl_dump_ex(int type, char *data, size_t len) {
  if (len == 0) return;
  if (!(type & qrl_log_level)) return;

  size_t cur = 0;

  for (; cur < 16 * (len / 16); cur += 16) {
    qrl_dump_decode_binary(data + cur, 16);
    printf("| ");
    qrl_dump_decode_ascii(data + cur, 16);
    printf(" |");
    puts("");
  }
  /* write the remaining */
  if (len % 16) {
    qrl_dump_decode_binary(data + cur, len % 16);
    /* write the empty */
    for (int i = 0; i < 16 - (len % 16); i++) {
      printf("   ");
      if (i == 7) putchar(' ');
    }

    printf("| ");
    qrl_dump_decode_ascii(data + cur, len % 16);
    for (int i = 0; i < 16 - (len % 16); i++) {
      putchar(' ');
    }
    printf(" |");
    puts("");
    cur += len % 16;
  }
  assert(len == cur);
}

void qrl_dump(char *data, size_t len) { qrl_dump_ex(QRL_LOG_INFO, data, len); }

void qrl_printx(uint8_t *x, size_t len) {
  for (size_t i = 0; i < len; i++) printf("%02x", x[i]);
  puts("");
}

#ifdef MAP_NOCORE
#  define QRL_MAP_NOCORE MAP_NOCORE
#else
#  define QRL_MAP_NOCORE 0
#endif

#ifdef MAP_CONCEAL
#  define QRL_MAP_CONCEAL MAP_CONCEAL
#else
#  define QRL_MAP_CONCEAL 0
#endif

/* special function for allocating sensitive memory for private keys */
/* MUST ONLY BE FREED by qrl_free_secure_page()
 */
void *qrl_alloc_secure_page() {
  void *mem = mmap(
      NULL, getpagesize(), PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | QRL_MAP_NOCORE | QRL_MAP_CONCEAL, -1, 0);
  if (mem == MAP_FAILED) {
    QRL_LOG_EX(QRL_LOG_ERROR, "mmap()");
    perror("");
    return NULL;
  }

  /* lock secure page */
  if (mlock(mem, getpagesize())) {
    QRL_LOG_EX(QRL_LOG_ERROR, "failed to lock memory %p\n", mem);
    munmap(mem, getpagesize());
    return NULL;
  }

  return mem;
}

void qrl_free_secure_page(void *mem) {
  if (mem == NULL) return;
  memset(mem, 0xaa, getpagesize());
  memset(mem, 0x55, getpagesize());
  memset(mem, 0x0f, getpagesize());
  memset(mem, 0xf0, getpagesize());
  memset(mem, 0x00, getpagesize());

  if (munlock(mem, getpagesize())) {
    QRL_LOG_EX(QRL_LOG_WARNING, "failed to unlock memory %p\n", mem);
  }

  munmap(mem, getpagesize());
  QRL_LOG_EX(QRL_LOG_TRACE, "freed %d bytes on %p\n", getpagesize(), mem);
}

void *qrl_malloc(size_t s) {
  void *mem = malloc(s);
  if (mem == NULL) {
    QRL_LOG_EX(QRL_LOG_WARNING, "couldn't allocated %d bytes\n", s);
    return NULL;
  }
  return mem;
}

void *qrl_calloc(size_t n, size_t s) {
  void *mem = calloc(n, s);
  if (mem == NULL) {
    QRL_LOG_EX(QRL_LOG_WARNING, "couldn't allocated %d bytes\n", n * s);
    return NULL;
  }
  return mem;
}

void qrl_free(void *mem) {
  if (mem == NULL) return;
  free(mem);
}
