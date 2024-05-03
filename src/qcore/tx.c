#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"
#include "hash.h"

#include "include/types.h"
#include "dev_config.h"

#include <assert.h>

//extern int qrl_verify_sig(qvec_t pkey, qvec_t msg, qvec_t sig);
//extern qvec_t qrl_compute_hash_hdr(const qblock_hdr_t block_header, hfunc_ctx hfunc);
extern qvec_t qrl_compute_tx_transfer_hash(qtx_t tx);

qvec_t qrl_compute_tx_hash(qtx_t tx) {
  switch (tx.tx_type) {
    case QTX_TRANSFER:
      return qrl_compute_tx_transfer_hash(tx);
    case QTX_COINBASE: {
      size_t transaction_blob_len =
          tx.master_addr.len +
          tx.coinbase.addr_to.len +
          sizeof(tx.nonce) +
          sizeof(tx.coinbase.amount);

      char *transaction_blob = malloc(transaction_blob_len);
      assert(transaction_blob != NULL);

      struct inctr_t ctr = {0};
      size_t sincr = tx.master_addr.len;
      memcpy(transaction_blob + incrementp(&ctr, sincr), tx.master_addr.data, sincr);

      sincr = tx.coinbase.addr_to.len;
      memcpy(transaction_blob + incrementp(&ctr, sincr), tx.coinbase.addr_to.data, sincr);

      sincr = sizeof(tx.nonce);
      memcpy(transaction_blob + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(tx.nonce)}, sincr);

      sincr = sizeof(tx.coinbase.amount);
      memcpy(transaction_blob + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(tx.coinbase.amount)}, sincr);

      qvec_t transaction_hash = new_qvec(32);
      assert(transaction_hash.len >= 32);
      qrl_sha256(transaction_hash.data, transaction_blob, transaction_blob_len);
      QRL_LOG("transaction_hash coinbase: \n");
      qrl_dump(transaction_hash.data, transaction_hash.len);
      free(transaction_blob);
      return transaction_hash;
    }
    case QTX_LATTICEPK:
    case QTX_MESSAGE:
    case QTX_TOKEN:
    case QTX_TRANSFER_TOKEN:
    case QTX_SLAVE:
    case QTX_MULTISIG_CREATE:
    case QTX_MULTISIG_SPEND:
    case QTX_MULTISIG_VOTE:
    case QTX_PROPOSAL_CREATE:
    case QTX_PROPOSAL_VOTE:

    default:
      assert(0);
  }

  return QVEC_NULL;
}
