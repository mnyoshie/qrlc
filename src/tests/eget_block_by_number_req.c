#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <qrl.pb-c.h>

#include "utils.h"
#include "include/types.h"

int main(int argc, char *argv[]) {
  assert(argc == 2);
  size_t len;
  qu64 block_number = atoll(argv[1]);
  Qrl__GetBlockByNumberReq pb = QRL__GET_BLOCK_BY_NUMBER_REQ__INIT;
  pb.block_number = block_number;
  len = qrl__get_block_by_number_req__get_packed_size(&pb);
  qu8 *out = malloc(len);
  assert(out != NULL);
  len = qrl__get_block_by_number_req__pack(&pb, out);

  /* uncompressed */
  write(1, &(char){0}, 1);
  /* protobuf message length */
  write(1, &(qu32){QINT2BIG_32((qu32)len)}, 4);
  /* the actual message */
  write(1, out, len);
  free(out);
  return 0;
}
