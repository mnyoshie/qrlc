#ifndef QBLOCK_H

#include "include/types.h"


extern qvec_t qrl_compute_hash_hdr(const qblock_hdr_t *block_hdr, const hfunc_ctx *hfunc);
extern int qrl_verify_qblock(const qblock_t *qblock, const hfunc_ctx *hfunc);



#endif
