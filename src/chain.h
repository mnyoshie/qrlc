#ifndef QCHAIN_H
#define QCHAIN_H

#include <assert.h>
#include <leveldb/c.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "include/types.h"

typedef struct qchain_t qchain_t;
struct qchain_t {
  char state_dir[512];
  pthread_mutex_t state_mutex;
  leveldb_t *state;

  qu64 last_block;
};

extern qchain_t *qrl_open_chain(char *dir);
extern void qrl_close_chain(qchain_t *chain);
extern qblock_t *qrl_get_block_by_number(qchain_t *chain, qu64 block_number);
extern qu64 qrl_get_chain_height(qchain_t *chain);

extern void qrl_free_block(qblock_t *block);

#endif /* QCHAIN_H */
