#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"
#include "hash.h"

#include <assert.h>

static qvec_t get_data_hash(const qtx_t *tx) {
  assert(tx->tx_type == QTX_MESSAGE);
  size_t data_blob_len =
    tx->master_addr.len +
    sizeof(tx->fee) +
    tx->message.message_hash.len +
    tx->message.addr_to.len;
                      

  char *data_blob = malloc(data_blob_len);
  assert(data_blob != NULL);

  struct inctr_t ctr = {0};

  size_t sincr = tx->master_addr.len;
  memcpy(data_blob + incrementp(&ctr, sincr), tx->master_addr.data, sincr);

  sincr = sizeof(tx->fee);
  memcpy(data_blob + incrementp(&ctr, sincr), &(qu64){QINT2BIG_64(tx->fee)}, sincr);

  sincr = tx->message.message_hash.len;
  memcpy(data_blob + incrementp(&ctr, sincr), tx->message.message_hash.data, sincr);

  sincr = tx->message.addr_to.len;
  memcpy(data_blob + incrementp(&ctr, sincr), tx->message.addr_to.data, sincr);

  qvec_t data_hash = qrl_qvecmalloc(32);
  qrl_sha256(data_hash.data, data_blob, data_blob_len);
  free(data_blob);

  return data_hash;
}

qvec_t qrl_compute_qtx_message_hash(const qtx_t *tx) {
  assert(tx->tx_type == QTX_MESSAGE);
  struct inctr_t ctr = {0};
  size_t sincr = 0;
  qvec_t data_hash = get_data_hash(tx);

  /* transaction blob: data_hash + sig + epkey */
  size_t transaction_blob_len = data_hash.len + tx->signature.len + tx->public_key.len;
  uint8_t *transaction_blob = malloc(transaction_blob_len);
  assert(transaction_blob != NULL);

  ctr.i = 0;
  sincr = data_hash.len;
  memcpy(transaction_blob + incrementp(&ctr, sincr), data_hash.data, sincr);

  sincr = tx->signature.len;
  memcpy(transaction_blob + incrementp(&ctr, sincr), tx->signature.data, sincr);

  sincr = tx->public_key.len;
  memcpy(transaction_blob + incrementp(&ctr, sincr), tx->public_key.data, sincr);
  qvec_t tx_hash = qrl_qvecmalloc(32);

  qrl_sha256(tx_hash.data, transaction_blob, transaction_blob_len);

  free(data_hash.data);
  free(transaction_blob);

  return tx_hash;
}

int qrl_verify_qtx_message(qtx_t *tx) {
  assert(tx->tx_type == QTX_MESSAGE);
  int ret = 0xff;
  qvec_t tx_hash = qrl_compute_qtx_message_hash(tx);
  assert(tx_hash.len == 32);
  assert(tx->tx_hash.len == 32);
#define EXITIF(x, fmt, ...)                           \
  do {                                                \
    if (x) {                                          \
      QLOGX(QLOG_ERROR, #x ": " __VA_ARGS__); \
      goto exit;                                      \
    }                                                 \
  } while (0)

  EXITIF(memcmp(tx_hash.data, tx->tx_hash.data, 32), "transaction hash mismatch\n");
  EXITIF(tx->message.message_hash.len > 80, "message transaction exceeds 80 bytes\n");
//if (memcmp(tx_hash.data, tx->tx_hash.data, 32)) {
//    QLOGX(QLOG_ERROR, "transaction hash mismatch\n");
//    goto exit;
//  }
//  if (tx->message.len > 80) {
//    QLOGX(QLOG_ERROR, "message tran\n");
//    goto exit;
//  }
#undef EXITIF
  ret ^= ret;

exit:
  free(tx_hash.data);
  return ret;
}
