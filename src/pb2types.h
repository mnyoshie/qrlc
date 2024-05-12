#ifndef QPB2TYPES_H
#define QPB2TYPES_H
#include <stdlib.h>
#include <assert.h>
#include "qrl.pb-c.h"
#include "log.h"
#include "utils.h"
#include "include/types.h"


//extern qblock_t *pbblock_blockt(const qvec_t *block);
//extern qvec_t blockt_pbblock(const qblock_t *block);
extern qblock_t *unpack_qblock(const qvec_t *block);
extern qvec_t pack_qblock(const qblock_t *qblock);
extern qblock_t *pbblock_to_qblock(Qrl__Block *pbblock);

#endif /* QPB2TYPES_H */
