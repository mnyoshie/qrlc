#ifndef QPB2TYPES_H
#define QPB2TYPES_H
#include "qrl.pb-c.h"
#include "include/types.h"


//extern qblock_t *pbblock_blockt(const qvec_t *block);
//extern qvec_t blockt_pbblock(const qblock_t *block);
extern qblock_t *unpack_qblock(const qvec_t *block);
extern qvec_t pack_qblock(const qblock_t *qblock);
extern qvec_t pack_qtx(const qtx_t *qtx);
extern qblock_t *pbblock_to_qblock(Qrl__Block *pbblock);

extern Qrl__Transaction *qtx_to_pbtx(const qtx_t *qtx);

#endif /* QPB2TYPES_H */
