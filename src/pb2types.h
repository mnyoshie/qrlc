#ifndef QPB2TYPES_H
#define QPB2TYPES_H
#include <stdlib.h>
#include <assert.h>
#include "qrl.pb-c.h"
#include "include/types.h"


extern qblock_t *pbblock_blockt(const qvec_t *block);
extern qvec_t blockt_pbblock(const qblock_t *block);

#endif /* QPB2TYPES_H */
