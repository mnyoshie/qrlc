/* pb2types.c - protobuf serialized data to internal types conversion and vice
 * versa.
 *
 * To deal with portability issues arising from future modification to qrl.proto
 */

#include "pb2types.h"

qblock_t *pbblock_blockt(const qvec_t *block) {
  Qrl__Block *msg;

   msg = qrl__block__unpack(NULL, block->len, block->data);

   qrl__block__free_unpacked(msg, NULL);

  return NULL;
}

qvec_t blockt_pbblock(const qblock_t *block) {
  Qrl__Block msg;
  void *data;
  size_t len;

  qrl__block__init(&msg); 

  len = qrl__block__get_packed_size(&msg);
  data = malloc(len);
  assert(data != NULL);

  qrl__block__pack(&msg, data);


  return (qvec_t){.data=data, .len=len};
}
