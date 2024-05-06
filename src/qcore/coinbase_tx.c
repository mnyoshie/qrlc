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

  qvec_t transaction_hash = new_qvec(32);
  qrl_sha256(transaction_hash.data, transaction_blob, transaction_blob_len);
//  QRL_LOG("transaction_hash coinbase: \n");
//  qrl_dump(transaction_hash.data, transaction_hash.len);
  free(transaction_blob);
  return transaction_hash;
}

int qrl_verify_qtx_coinbase(const qtx_t *tx) {
 return 0;
}
