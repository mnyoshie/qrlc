/* qchain.c - qrlc chain manager 
 *
 * Copyright (c) 2024 Minato Nakamura Yoshie
 *
 * Released under MIT
 */

//#define _FILE_OFFSET_BITS 64

#include <string.h>
#include <inttypes.h>
#include <json-c/json.h>

#include "chain.h"
#include "utils.h"

qchain_t *qrl_open_chain(char *dir) {
  qchain_t *chain;
  leveldb_t *state;
  leveldb_options_t *options;
  leveldb_writeoptions_t *woptions;

  char *err = NULL; 


  options = leveldb_options_create();
  leveldb_options_set_create_if_missing(options, 0);
  state = leveldb_open(options, dir, &err);

  if (err != NULL) {
    QRL_LOG_EX(QRL_LOG_ERROR, "%s: state open fail\n", err);
    leveldb_free(err);
    return NULL;
  }


  chain  = malloc(sizeof(*chain));
  assert(chain != NULL);
  chain->state = state;
  strncpy(chain->state_dir, dir, 511);
  return chain;
}

void qrl_close_chain(qchain_t *chain) {
  leveldb_close(chain->state);
  free(chain);
}

qblock_t *qrl_get_block_by_number(qchain_t *chain, qu64 block_number) {
  leveldb_readoptions_t *roptions;
  struct json_object *jobj;
  struct json_object *header_hash, *pheader_hash;
  char *err = NULL, *read = NULL;
  size_t read_len;
  char key[512] = {0};

  snprintf(key, 511, "%" PRIu64, block_number);

  roptions = leveldb_readoptions_create();
  read = leveldb_get(chain->state, roptions, key, strlen(key), &read_len, &err);

  if (err != NULL) {
    QRL_LOG_EX(QRL_LOG_ERROR, "%s: leveldb: %s. failed on block %s (%"PRIx64")\n", chain->state_dir, err, key, block_number);
    leveldb_free(err);
    return NULL;
  }
  if (read == NULL) {
    QRL_LOG_EX(QRL_LOG_ERROR, "%s: can't find block %s (%"PRIx64")\n", chain->state_dir, key, block_number);
    return NULL;
  }

  write(1, read, read_len);

  {
    /* inside read is a non null terminated json. we have to deal with this */
    char *jstr = calloc(1, read_len + 1);
    memcpy(jstr, read, read_len);
    jobj = json_tokener_parse(jstr);
    header_hash = json_object_object_get(jobj, "headerhash"); 
    pheader_hash = json_object_object_get(jobj, "prevHeaderhash");
  
    puts(json_object_get_string(header_hash)); 
    puts(json_object_get_string(pheader_hash));
    json_object_put(jobj); // free 
    free(jstr);
  }

 

  return NULL;
}

void qrl_free_block(qblock_t *block) {

  free(block);
}

