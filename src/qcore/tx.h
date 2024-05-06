#ifndef QTX_H
#define QTX_H

#include "include/types.h"

extern qvec_t qrl_compute_tx_hash(const qtx_t *tx);
extern int qrl_verify_qtx(const qtx_t *tx);

#endif
