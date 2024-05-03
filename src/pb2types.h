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
extern qblock_t *qblock_unpack(const qvec_t *block);
extern qvec_t qblock_pack(const qblock_t *qblock);

#endif /* QPB2TYPES_H */
