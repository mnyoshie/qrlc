#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"
#include "hash.h"
#include "xmssf.h"

#include "dev_config.h"

#include <assert.h>

static qvec_t get_data_hash(const qtx_t *tx) {
  assert(tx->tx_type == QTX_TRANSFER);

  struct inctr_t ctr = {0};
  size_t sincr = 0;
  if (tx->transfer.nb_amounts != tx->transfer.nb_addrs_to) {
    QRL_LOG_EX(QRL_LOG_ERROR, "malformed tx-> %d (n_addrs) != %d (n_ammounts)\n",
               tx->transfer.nb_addrs_to, tx->transfer.nb_amounts);
    return QVEC_NULL;
  }

  size_t data_blob_len =
      tx->master_addr.len + sizeof(tx->fee) + tx->transfer.message_data.len;

  // tmptxhash = (self.master_addr +
  //                      self.fee.to_bytes(8, byteorder='big',
  //                      signed=False) + self.message_data) for index in
  //                      range(0, len(self.addrs_to)): tmptxhash =
  //                      (tmptxhash +
  //                          self.addrs_to[index] +
  //                          self.amounts[index].to_bytes(8,
  //                          byteorder='big', signed=False))
  //
  //         return tmptxhash
  for (size_t i = 0; i < tx->transfer.nb_addrs_to; i++)
    data_blob_len +=
        tx->transfer.addrs_to[i].len + sizeof(tx->transfer.amounts[i]);

  uint8_t *data_blob = malloc(data_blob_len);

  assert(data_blob != NULL);

  sincr = tx->master_addr.len;
  memcpy(data_blob + incrementp(&ctr, sincr), tx->master_addr.data, sincr);
  sincr = sizeof(uint64_t);
  memcpy(data_blob + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(tx->fee)},
         sincr);
  sincr = tx->transfer.message_data.len;
  memcpy(data_blob + incrementp(&ctr, sincr), tx->transfer.message_data.data,
         sincr);

  do {
    size_t seek = ctr.i;

    for (size_t i = 0; i < tx->transfer.nb_addrs_to; i++) {
      memcpy(data_blob + seek, tx->transfer.addrs_to[i].data, tx->transfer.addrs_to[i].len);
      seek += tx->transfer.addrs_to[i].len;
      memcpy(data_blob + seek, &(uint64_t){QINT2BIG_64(tx->transfer.amounts[i])}, sizeof(tx->transfer.amounts[i]));
      seek += sizeof(tx->transfer.amounts[i]);
    }
    assert(seek == data_blob_len);
  } while (0);

  qvec_t data_hash = new_qvec(32);
  assert(data_hash.data != NULL);

  qrl_sha256(data_hash.data, data_blob, data_blob_len);
  free(data_blob);

  return data_hash;

}

qvec_t qrl_compute_qtx_transfer_hash(const qtx_t *tx) {
  assert(tx->tx_type == QTX_TRANSFER);
  struct inctr_t ctr = {0};
  size_t sincr = 0;
  qvec_t data_hash = get_data_hash(tx);

//  QRL_LOG("data hash: ");
//  qrl_printx(data_hash, 32);
//  if (qrl_verify_sig(
//          (qvec_t){.len = tx->public_key.len, .data = tx->public_key.data},  //
//          (qvec_t){.len = 32, .data = data_hash},                          //
//          (qvec_t){.len = tx->signature.len, .data = tx->signature.data})) {
//    QRL_LOG_EX(QRL_LOG_ERROR, "invalid signature\n");
//    //return QVEC_NULL;
//  }

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
  qvec_t transaction_hash = new_qvec(32);

  qrl_sha256(transaction_hash.data, transaction_blob, transaction_blob_len);
//  QRL_LOG("computed transaction hash\n");
//  qrl_dump(transaction_hash.data, transaction_hash.len);

  free(data_hash.data);
  free(transaction_blob);

  return transaction_hash;
}

int qrl_verify_qtx_transfer(const qtx_t *tx) {
  int ret = 0xff;
  qvec_t tx_hash = QVEC_NULL;
  qvec_t data_hash =  get_data_hash(tx);
  assert(data_hash.data != NULL);

//  QRL_LOG("data hash: ");
//  qrl_printx(data_hash.data, 32);
  if (qrl_verify_sig(
          (qvec_t){.len = tx->public_key.len, .data = tx->public_key.data},  //
          (qvec_t){.len = data_hash.len, .data = data_hash.data},                          //
          (qvec_t){.len = tx->signature.len, .data = tx->signature.data})) {
    QRL_LOG_EX(QRL_LOG_ERROR, "invalid signature\n");
    goto exit;
  }

 
  tx_hash = qrl_compute_qtx_transfer_hash(tx);
  assert(tx_hash.len == 32);
  assert(tx->transaction_hash.len == 32);
  if (memcmp(tx_hash.data, tx->transaction_hash.data, 32)) {
    QRL_LOG_EX(QRL_LOG_ERROR, "transaction hash mismatch\n");
    goto exit;
  }

  ret ^= ret;
exit:
  free(data_hash.data);
  free(tx_hash.data);
  return ret;
}
