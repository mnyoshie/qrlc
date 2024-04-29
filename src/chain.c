/* qchain.c - qrlc chain manager
 *
 * Copyright (c) 2024 Minato Nakamura Yoshie
 *
 * Released under MIT
 */

// #define _FILE_OFFSET_BITS 64

#include "chain.h"

#include <inttypes.h>
#include <json-c/json.h>
#include <string.h>

#include "base64.h"
#include "include/b64/cdecode.h"
#include "include/b64/cencode.h"
#include "pb2types.h"
#include "utils.h"

qchain_t *qrl_open_chain(char *dir) {
  qchain_t *chain;
  leveldb_t *state;
  leveldb_options_t *options;
  // leveldb_writeoptions_t *woptions;

  char *err = NULL;

  options = leveldb_options_create();
  leveldb_options_set_create_if_missing(options, 0);
  state = leveldb_open(options, dir, &err);

  if (err != NULL) {
    QRL_LOG_EX(QRL_LOG_ERROR, "%s: state open fail\n", err);
    leveldb_free(err);
    return NULL;
  }

  chain = malloc(sizeof(*chain));
  assert(chain != NULL);
  chain->state = state;
  strncpy(chain->state_dir, dir, 511);
  return chain;
}

void qrl_close_chain(qchain_t *chain) {
  leveldb_close(chain->state);
  free(chain);
}

qvec_t qrl_get_headerhash_by_number(qchain_t *chain, qu64 block_number) {
  leveldb_readoptions_t *roptions;
  struct json_object *jobj, *headerhash;
  char *jstr = NULL;

  char *value = NULL;
  size_t valuelen;
  qvec_t v = {.data=NULL, .len=0};
  char key[512] = {0};
  char *err = NULL;

  snprintf(key, 511, "%" PRIu64, block_number);

  roptions = leveldb_readoptions_create();
  assert(roptions != NULL);

  value = leveldb_get(chain->state, roptions, key, strlen(key), &valuelen, &err);

  if (err != NULL) {
    QRL_LOG_EX(QRL_LOG_ERROR,
               "%s: leveldb: %s. failed on block %s (%" PRIx64 ")\n",
               chain->state_dir, err, key, block_number);
    goto exit;
  }

  if (value == NULL) {
    QRL_LOG_EX(QRL_LOG_ERROR, "%s: can't find block %s (%" PRIx64 ")\n",
               chain->state_dir, key, block_number);
    goto exit;
  }

  //  write(1, read, valuelen);

  /* inside read is a non null terminated json. we have to deal with this */
  jstr = calloc(1, valuelen + 1);
  memcpy(jstr, value, valuelen);
  jobj = json_tokener_parse(jstr);
  headerhash = json_object_object_get(jobj, "headerhash");

  const char *str_hh = json_object_get_string(headerhash);
  //?puts(str_hh);

  v = qrl_decode_base64(str_hh);  // XXX
  // qrl_dump(v.data, v.len);
  json_object_put(jobj);  // free

exit:
  free(jstr);
  leveldb_free(err);
  leveldb_free(value);
  leveldb_readoptions_destroy(roptions);

  return v;
}

qblock_t *qrl_get_block_by_number(qchain_t *chain, qu64 block_number) {
  qblock_t *block = NULL;
  leveldb_readoptions_t *roptions = NULL;
  char *value = NULL;
  size_t valuelen;
  char *err = NULL;

  qvec_t headerhash = qrl_get_headerhash_by_number(chain, block_number);
  if (headerhash.data == NULL) {
    QRL_LOG_EX(QRL_LOG_ERROR,
               "%s: failed to retrieve headerhash (%" PRIx64 ")\n",
               chain->state_dir, block_number);
    goto exit;
  }

  roptions = leveldb_readoptions_create();
  value = leveldb_get(chain->state, roptions, (void*)headerhash.data, headerhash.len,
                      &valuelen, &err);

  if (err != NULL) {
    QRL_LOG_EX(QRL_LOG_ERROR,
               "%s: leveldb: %s. failed on block (%" PRIx64 ")\n",
               chain->state_dir, err, block_number);
    goto exit;
  }
  // qrl_dump(value, valuelen);
  write(1, value, valuelen);
  /* deserialize Block */
  block = pbblock_blockt(&(qvec_t){.data = (void*)value, .len = valuelen});

exit:
  leveldb_free(err);
  leveldb_free(value);
  leveldb_readoptions_destroy(roptions);
  free(headerhash.data);

  return block;
}

void qrl_free_block(qblock_t *block) { free(block); }