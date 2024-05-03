#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"
#include "hash.h"
#include "chain.h"

#include "include/types.h"

#include "dev_config.h"
//#include "include/qrl.pb-c.h"

#ifdef NDEBUG
#  error "Don't turn NDEBUG!"
#endif

#include <assert.h>

extern int qrl_verify_sig(qvec_t pkey, qvec_t msg, qvec_t sig);

qvec_t qrl_compute_tx_transfer_hash(qtx_t tx) {
  assert(tx.tx_type == QTX_TRANSFER);

  struct inctr_t ctr = {0};
  size_t sincr = 0;
  if (tx.transfer.n_amounts != tx.transfer.n_addrs_to) {
    QRL_LOG_EX(QRL_LOG_ERROR, "malformed tx. %d (n_addrs) != %d (n_ammounts)\n",
               tx.transfer.n_addrs_to, tx.transfer.n_amounts);
    return QVEC_NULL;
  }

  size_t data_blob_len =
      tx.master_addr.len + sizeof(tx.fee) + tx.transfer.message_data.len;

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
  for (size_t i = 0; i < tx.transfer.n_addrs_to; i++)
    data_blob_len +=
        tx.transfer.addrs_to[i].len + sizeof(tx.transfer.amounts[i]);

  uint8_t *data_blob = malloc(data_blob_len);

  assert(data_blob != NULL);

  sincr = tx.master_addr.len;
  memcpy(data_blob + incrementp(&ctr, sincr), tx.master_addr.data, sincr);
  sincr = sizeof(uint64_t);
  memcpy(data_blob + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(tx.fee)},
         sincr);
  sincr = tx.transfer.message_data.len;
  memcpy(data_blob + incrementp(&ctr, sincr), tx.transfer.message_data.data,
         sincr);

  do {
    size_t seek = ctr.i;

    for (qu32 i = 0; i < tx.transfer.n_addrs_to; i++) {
      memcpy(data_blob + seek, tx.transfer.addrs_to[i].data,
             tx.transfer.addrs_to[i].len);
      seek += tx.transfer.addrs_to[i].len;
      memcpy(data_blob + seek, &(uint64_t){QINT2BIG_64(tx.transfer.amounts[i])},
             sizeof(tx.transfer.amounts[i]));
      seek += sizeof(tx.transfer.amounts[i]);
    }
    assert(seek == data_blob_len);
  } while (0);

  uint8_t data_hash[32];
  qrl_sha256(data_hash, data_blob, data_blob_len);
  free(data_blob);

  QRL_LOG("data hash: ");
  qrl_printx(data_hash, 32);
  if (qrl_verify_sig(
          (qvec_t){.len = tx.public_key.len, .data = tx.public_key.data},  //
          (qvec_t){.len = 32, .data = data_hash},                          //
          (qvec_t){.len = tx.signature.len, .data = tx.signature.data})) {
    QRL_LOG_EX(QRL_LOG_ERROR, "invalid signature\n");
    return QVEC_NULL;
  }

  /* transaction blob: data_hash + sig + epkey */
  size_t transaction_blob_len = 32 + tx.signature.len + tx.public_key.len;
  uint8_t *transaction_blob = malloc(transaction_blob_len);
  assert(transaction_blob != NULL);

  sincr = 32;
  memcpy(transaction_blob + incrementp(&ctr, sincr), data_hash, sincr);

  sincr = tx.signature.len;
  memcpy(transaction_blob + incrementp(&ctr, sincr), tx.signature.data, sincr);

  sincr = tx.public_key.len;
  memcpy(transaction_blob + incrementp(&ctr, sincr), tx.public_key.data, sincr);
  qvec_t transaction_hash = new_qvec(32);

  qrl_sha256(transaction_hash.data, transaction_blob, transaction_blob_len);
  QRL_LOG("computed transaction hash\n");
  qrl_dump(transaction_hash.data, transaction_hash.len);

  return transaction_hash;
}
