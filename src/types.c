#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>

#include "log.h"
#include "utils.h"
#include "include/types.h"

/* free qvec */
void free_qvec(qvec_t *q){
  free(q->data);
  free(q);
}


qvec_t *malloc_qvec(size_t size){
  qvec_t *q = malloc(sizeof(*q));
  assert(q != NULL);

  q->len = size;
  q->data = malloc(size);

  assert(q->data != NULL);
  return q;
}

qvec_t new_qvec(size_t size){
  qu8 *q = calloc(1, size);
  assert(q != NULL);

  return (qvec_t){.data=q, .len=size};
}

/* delete qvec */
void del_qvec(qvec_t q){
  free(q.data);
  q.len = 0;
}

void *qrl_memcat(void *data1, size_t len1, void *data2, size_t len2) {
  char *ret = malloc(len1 + len2);
  assert(ret != NULL);

  memcpy(ret, data1, len1);
  memcpy(ret + len1, data2, len2);

  free(data1);
  free(data2);
  return ret;
}

void print_qblock(qblock_t *qblock) {
//  qvec_t hash_hdr;
//  qu64 block_number;
//
//  // unix since epoch jan 1, 1970
//  qu64 timestamp; 
//
////  size_t pheader_hash_len;
////  qu8 *pheader_hash;
//  qvec_t hash_phdr;
//
//  qu64 reward_block;
//  qu64 reward_fee;
//
//  qvec_t merkle_root;
////  size_t merkle_root_len;
////  qu8 *merkle_root;
//
//  qu64 mining_nonce;
//  qu64 extra_nonce;
#define PRINT_FIELD_DATA(a, x) printf(a #x ": "); qrl_printx(qblock-> x .data, qblock-> x .len)
#define PRINT_FIELD_U32(a, x) printf(a #x ": %"PRIu32"\n", qblock-> x)
#define PRINT_FIELD_U64(a, x) printf(a #x ": %"PRIu64"\n", qblock-> x)
  PRINT_FIELD_U64("", block_hdr.block_number);
  PRINT_FIELD_U64("", block_hdr.timestamp);
  PRINT_FIELD_U64("", block_hdr.reward_block);
  PRINT_FIELD_U64("", block_hdr.reward_fee);
  PRINT_FIELD_U32("", block_hdr.mining_nonce);
  PRINT_FIELD_U64("", block_hdr.extra_nonce);

  PRINT_FIELD_DATA("", block_hdr.hash_hdr);
  PRINT_FIELD_DATA("", block_hdr.hash_phdr);
  PRINT_FIELD_DATA("", block_hdr.merkle_root);
  for (size_t i = 0; i < qblock->nb_txs; i++) {
    PRINT_FIELD_U32("  ", txs[i].tx_type);
    PRINT_FIELD_DATA("  ", txs[i].master_addr);
    PRINT_FIELD_DATA("  ", txs[i].signature);
    PRINT_FIELD_DATA("  ", txs[i].public_key);
    PRINT_FIELD_DATA("  ", txs[i].transaction_hash);
    PRINT_FIELD_U64("  ", txs[i].fee);
    PRINT_FIELD_U64("  ", txs[i].nonce);
    switch (qblock->txs[i].tx_type) {
      case QTX_TRANSFER:
        PRINT_FIELD_DATA("  ", txs[i].transfer.message_data);
        break;
      case QTX_COINBASE:
        PRINT_FIELD_DATA("    ", txs[i].coinbase.addr_to);
        PRINT_FIELD_U64("    ", txs[i].coinbase.amount);
        break;
      default: QRL_LOG_EX(QRL_LOG_ERROR, "  transaction type %d\n",qblock->txs[i].tx_type);
    }
    puts("");
  }
#undef PRINT_FIELD_DATA
#undef PRINT_FIELD_U32
#undef PRINT_FIELD_U64
}

void free_qblock(qblock_t *qblock) {
  free(qblock->block_hdr.hash_hdr.data);
  free(qblock->block_hdr.hash_phdr.data);
  free(qblock->block_hdr.merkle_root.data);
  /**************TRANSACTIONS***************************/
  for (size_t i = 0; i < qblock->nb_txs; i++) {
    free(qblock->txs[i].master_addr.data);
    free(qblock->txs[i].public_key.data);
    free(qblock->txs[i].signature.data);
    free(qblock->txs[i].transaction_hash.data);
    switch (qblock->txs[i].tx_type) {
      case QTX_TRANSFER:
        for (size_t t = 0; t < qblock->txs[i].transfer.n_addrs_to; t++)
          free(qblock->txs[i].transfer.addrs_to[t].data);

        free(qblock->txs[i].transfer.message_data.data);
        assert(qblock->txs[i].transfer.n_addrs_to == qblock->txs[i].transfer.n_amounts);
        break;

      case QTX_COINBASE:
        free(qblock->txs[i].coinbase.addr_to.data);
        break;
      default: QRL_LOG_EX(QRL_LOG_ERROR, "unknown transaction type %d\n",qblock->txs[i].tx_type);  assert(0);
    }
  }
  free(qblock->txs);

  free(qblock);
}
