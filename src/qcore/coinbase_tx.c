#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"
#include "hash.h"

#include <assert.h>

//extern qvec_t qrl_compute_tx_transfer_hash(const qtx_t *tx);

qvec_t qrl_compute_qtx_coinbase_hash(const qtx_t *tx) {
  assert(tx->tx_type == QTX_COINBASE);
  size_t transaction_blob_len = tx->master_addr.len + tx->coinbase.addr_to.len +
                                sizeof(tx->nonce) + sizeof(tx->coinbase.amount);

  char *transaction_blob = malloc(transaction_blob_len);
  assert(transaction_blob != NULL);

  struct inctr_t ctr = {0};
  size_t sincr = tx->master_addr.len;
  memcpy(transaction_blob + incrementp(&ctr, sincr), tx->master_addr.data,
         sincr);

  sincr = tx->coinbase.addr_to.len;
  memcpy(transaction_blob + incrementp(&ctr, sincr), tx->coinbase.addr_to.data,
         sincr);

  sincr = sizeof(tx->nonce);
  memcpy(transaction_blob + incrementp(&ctr, sincr),
         &(uint64_t){QINT2BIG_64(tx->nonce)}, sincr);

  sincr = sizeof(tx->coinbase.amount);
  memcpy(transaction_blob + incrementp(&ctr, sincr),
         &(uint64_t){QINT2BIG_64(tx->coinbase.amount)}, sincr);

  qvec_t tx_hash = new_qvec(32);
  qrl_sha256(tx_hash.data, transaction_blob, transaction_blob_len);
//  QRL_LOG("computed transaction hash\n");
//  qrl_dump(tx_hash.data, tx_hash.len);
  free(transaction_blob);
  return tx_hash;
}

int qrl_verify_qtx_coinbase(const qtx_t *tx) {
  int ret = 0xff;
  char master_addr[32] = {0};
  qvec_t tx_hash = qrl_compute_qtx_coinbase_hash(tx);
  assert(tx_hash.len == 32);

  if (tx->tx_hash.len != 32 && memcmp(tx_hash.data, tx->tx_hash.data, 32)) {
    QRL_LOG_EX(QRL_LOG_ERROR, "transaction hash mismatch\n");
    goto exit;
  }
  if (tx->master_addr.len != 32 && memcmp(master_addr, tx->master_addr.data, 32)) {
    QRL_LOG_EX(QRL_LOG_ERROR, "invalid master addr\n");
    goto exit;
  }
  ret ^= ret;

exit:
  free(tx_hash.data);
  return ret;
}
