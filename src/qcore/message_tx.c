#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"
#include "hash.h"

#include <assert.h>

qvec_t qrl_compute_qtx_message_hash(const qtx_t *tx) {
  assert(tx->tx_type == QTX_COINBASE);
  size_t transaction_blob_len =
    tx->master_addr.len +
    sizeof(tx->fee) +
    tx->message.message_hash.len +
    tx->message.addr_to.len;
                      

  char *transaction_blob = malloc(transaction_blob_len);
  assert(transaction_blob != NULL);

  struct inctr_t ctr = {0};

  size_t sincr = tx->master_addr.len;
  memcpy(transaction_blob + incrementp(&ctr, sincr), tx->master_addr.data, sincr);

  sincr = sizeof(tx->fee);
  memcpy(transaction_blob + incrementp(&ctr, sincr), &(qu64){QINT2BIG_64(tx->fee)}, sincr);

  sincr = tx->message.message_hash.len;
  memcpy(transaction_blob + incrementp(&ctr, sincr), tx->message.message_hash.data, sincr);

  sincr = tx->message.addr_to.len;
  memcpy(transaction_blob + incrementp(&ctr, sincr), tx->message.addr_to.data, sincr);

  qvec_t tx_hash = new_qvec(32);
  qrl_sha256(tx_hash.data, transaction_blob, transaction_blob_len);
//  QRL_LOG("computed transaction hash\n");
//  qrl_dump(tx_hash.data, tx_hash.len);
  free(transaction_blob);
  return tx_hash;
}

int qrl_verify_qtx_message(qtx_t *tx) {
  assert(tx->tx_type == QTX_MESSAGE);
  int ret = 0xff;
  qvec_t tx_hash = qrl_compute_qtx_message_hash(tx);
  assert(tx_hash.len == 32);
  assert(tx->tx_hash.len == 32);
  if (memcmp(tx_hash.data, tx->tx_hash.data, 32)) {
    QRL_LOG_EX(QRL_LOG_ERROR, "transaction hash mismatch\n");
    goto exit;
  }
  ret ^= ret;

exit:
  free(tx_hash.data);
  return ret;
}
