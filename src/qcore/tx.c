#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"
#include "hash.h"

#include "include/types.h"

#include <assert.h>

extern qvec_t qrl_compute_tx_transfer_hash(qtx_t tx);
extern qvec_t qrl_compute_tx_coinbase_hash(qtx_t tx);

qvec_t qrl_compute_tx_hash(qtx_t tx) {
  switch (tx.tx_type) {
    case QTX_COINBASE:
      return qrl_compute_tx_coinbase_hash(tx);
    case QTX_TRANSFER:
      return qrl_compute_tx_transfer_hash(tx);
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
