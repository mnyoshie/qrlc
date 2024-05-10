#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"
#include "hash.h"
#include "tx.h"
//#include "coinbase_tx.h"
//#include "transfer_tx.h"

#include "include/types.h"

#include <assert.h>

extern qvec_t qrl_compute_qtx_transfer_hash(const qtx_t *tx);
extern qvec_t qrl_compute_qtx_coinbase_hash(const qtx_t *tx);
extern int qrl_verify_qtx_coinbase(const qtx_t *tx);
extern int qrl_verify_qtx_transfer(const qtx_t *tx);
extern int qrl_verify_qtx_message(const qtx_t *tx);

qvec_t qrl_compute_tx_hash(const qtx_t *tx) {
  switch (tx->tx_type) {
    case QTX_COINBASE:
      return qrl_compute_qtx_coinbase_hash(tx);
    case QTX_TRANSFER:
      return qrl_compute_qtx_transfer_hash(tx);
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

int qrl_verify_qtx(const qtx_t *tx) {
  int ret = 0xff;
//  qvec_t tx_hash = qrl_compute_tx_hash(tx);
//  assert(tx_hash.data != NULL);
//  assert(tx_hash.len == 32);
//  assert(tx->transaction_hash.len == 32);
//  if (memcmp(tx_hash.data, tx->transaction_hash.data, 32)) {
//    QRL_LOG_EX(QRL_LOG_ERROR, "transaction hash mismatch\n");
//    goto exit;
//  }
//

  switch (tx->tx_type) {
    case QTX_COINBASE:
      ret = qrl_verify_qtx_coinbase(tx);
      goto exit;                   
    case QTX_TRANSFER:    
      ret = qrl_verify_qtx_transfer(tx);
      goto exit;
    case QTX_MESSAGE:
      ret = qrl_verify_qtx_message(tx);
      goto exit;
    default: assert(0);
  }

exit:
  //free(tx_hash.data);
  return ret;
}
