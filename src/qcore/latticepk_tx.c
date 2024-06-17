#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"
#include "hash.h"

#include <assert.h>

static qvec_t get_data_hash(const qtx_t *tx) {
  assert(tx->tx_type == QTX_LATTICEPK);
  size_t data_blob_len =
    tx->master_addr.len +
    sizeof(tx->fee) +
    tx->latticepk.pk1.len +
    tx->latticepk.pk2.len +
    tx->latticepk.pk3.len;
                      

  char *data_blob = malloc(data_blob_len);
  assert(data_blob != NULL);

  struct inctr_t ctr = {0};

  size_t sincr = tx->master_addr.len;
  memcpy(data_blob + incrementp(&ctr, sincr), tx->master_addr.data, sincr);

  sincr = sizeof(tx->fee);
  memcpy(data_blob + incrementp(&ctr, sincr), &(qu64){QINT2BIG_64(tx->fee)}, sincr);

  sincr = tx->latticepk.pk1.len;
  memcpy(data_blob + incrementp(&ctr, sincr), tx->latticepk.pk1.data, sincr);

  sincr = tx->latticepk.pk2.len;
  memcpy(data_blob + incrementp(&ctr, sincr), tx->latticepk.pk2.data, sincr);

  sincr = tx->latticepk.pk3.len;
  memcpy(data_blob + incrementp(&ctr, sincr), tx->latticepk.pk3.data, sincr);

  qvec_t data_hash = qrl_qvecmalloc(32);
  qrl_sha256(data_hash.data, data_blob, data_blob_len);
  free(data_blob);

  return data_hash;
}

qvec_t qrl_compute_qtx_latticepk_hash(const qtx_t *tx) {
  assert(tx->tx_type == QTX_TRANSFER);
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
//  QLOG("computed transaction hash\n");
//  qrl_dump(tx_hash.data, tx_hash.len);

  free(data_hash.data);
  free(transaction_blob);

  return tx_hash;
}

int qrl_verify_qtx_latticepk(qtx_t *tx) {
  assert(tx->tx_type == QTX_LATTICEPK);
  int ret = 0xff;
  qvec_t tx_hash = qrl_compute_qtx_latticepk_hash(tx);
  assert(tx_hash.len == 32);
  assert(tx->tx_hash.len == 32);
  if (memcmp(tx_hash.data, tx->tx_hash.data, 32)) {
    QLOGX(QLOG_ERROR, "transaction hash mismatch\n");
    goto exit;
  }
  ret ^= ret;

exit:
  free(tx_hash.data);
  return ret;
}
