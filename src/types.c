#include <stdio.h>
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

qvec_t qrl_qvecmalloc(size_t size){
  assert(size != 0);
  qu8 *q = calloc(1, size);
  assert(q != NULL);

  return (qvec_t){.data=q, .len=size};
}

/* delete qvec */
void qrl_qvecfree(qvec_t q){
  free(q.data);
  q.len = 0;
}

void *qrl_memcatf(void *data1, size_t len1, void *data2, size_t len2) {
  char *ret = malloc(len1 + len2);
  assert(ret != NULL);

  memcpy(ret, data1, len1);
  memcpy(ret + len1, data2, len2);

  free(data1);
  free(data2);
  return ret;
}

qvec_t qrl_qveccpy(const qvec_t a) {
  qvec_t v = qrl_qvecmalloc(a.len);
  memcpy(v.data, a.data, a.len);
  return v;
}

qvec_t qrl_qveccat(const qvec_t a, const qvec_t b) {
  void *data = malloc(a.len + b.len);
  assert(data != NULL);

  memcpy(data, a.data, a.len);
  memcpy(data + a.len, b.data, b.len);

  // XXX: assert a.len + b.len dont overflow 
  return (qvec_t){.data=data, .len=a.len + b.len};

}

void qrl_qvecdump(const qvec_t v){
  qrl_dump((void *)v.data, v.len); 
}

const char *qtx_type2str(qtx_type_t tx_type) {
  switch (tx_type) {
    case QTX_COINBASE: return "coinbase";
    case QTX_TRANSFER: return "transfer";
    case QTX_MESSAGE: return "message";
    case QTX_LATTICEPK: return "latticepk";
    default: return "unknown";
  }
}

void print_qblock(qblock_t *qblock, int verbose) {
#define PRINT_FIELD_DATA(a, x) do { printf(a #x ": (%zu bytes) ...\n", qblock-> x .len); if (verbose) qrl_dump(qblock-> x .data, qblock-> x .len); } while (0)
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
  printf("%zu transactions:\n", qblock->nb_txs);
  for (size_t i = 0; i < qblock->nb_txs; i++) {
    printf("  transaction #%zu:\n", i);
    printf("  txs[i].tx_type: %"PRIu32" (%s)\n", qblock->txs[i].tx_type,
        qtx_type2str(qblock->txs[i].tx_type));
    PRINT_FIELD_DATA("  ", txs[i].master_addr);
    PRINT_FIELD_DATA("  ", txs[i].signature);
    PRINT_FIELD_DATA("  ", txs[i].public_key);
    PRINT_FIELD_DATA("  ", txs[i].tx_hash);
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
      case QTX_MESSAGE:
        PRINT_FIELD_DATA("    ", txs[i].message.message_hash);
        PRINT_FIELD_DATA("    ", txs[i].message.addr_to);
      break;
      default: QLOGX(QLOG_ERROR, "  transaction type %d\n",qblock->txs[i].tx_type);
    }
    puts("");
  }
#undef PRINT_FIELD_DATA
#undef PRINT_FIELD_U32
#undef PRINT_FIELD_U64
}

void free_qtx(qtx_t qtx) {
  qrl_qvecfree(qtx.master_addr);
  qrl_qvecfree(qtx.public_key);
  qrl_qvecfree(qtx.signature);
  qrl_qvecfree(qtx.tx_hash);
  switch (qtx.tx_type) {
    case QTX_TRANSFER:
      for (size_t t = 0; t < qtx.transfer.nb_transfer_to; t++)
        qrl_qvecfree(qtx.transfer.addrs_to[t]);

      qrl_qvecfree(qtx.transfer.message_data);
      break;
    case QTX_COINBASE:
      qrl_qvecfree(qtx.coinbase.addr_to);
      break;
    case QTX_MESSAGE:
      qrl_qvecfree(qtx.message.message_hash);
      qrl_qvecfree(qtx.message.addr_to);
      break;
    case QTX_LATTICEPK:
      qrl_qvecfree(qtx.latticepk.pk1);
      qrl_qvecfree(qtx.latticepk.pk2);
      qrl_qvecfree(qtx.latticepk.pk3);
      break;
    case QTX_UNKNOWN:
      QLOGX(QLOG_WARNING, "unknown transaction type %d\n",qtx.tx_type); 
      break;
    default: QLOGX(QLOG_ERROR, "unknown transaction type %d\n",qtx.tx_type);  assert(0);
  }
}

void free_qblock(qblock_t qblock) {
  free(qblock.block_hdr.hash_hdr.data);
  free(qblock.block_hdr.hash_phdr.data);
  free(qblock.block_hdr.merkle_root.data);
  /**************TRANSACTIONS***************************/
  for (size_t i = 0; i < qblock.nb_txs; i++) {
    free_qtx(qblock.txs[i]);
  }
  free(qblock.txs);
}
