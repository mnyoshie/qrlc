#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <qrl.pb-c.h>

#include "hash.h"
#include "utils.h"
#include "pb2types.h"

#include "qcore/block.h"

#include "include/types.h"
#include "include/ansicolors.h"

int main() {
  //qrl_log_level = ~0 & ~QLOG_TRACE;
  qrl_log_level = 0;


  char buf[4096*10] = {0};
  size_t len = fread(buf, 1, 4096*10, stdin);
  assert(len > 5);
  /* uncompressed */
  assert(*buf == 0);
  /* verify message length. (FIXME may signal unaligned memory access) */
  /* expect to read one grpc message */
  if ((len - 5) != (size_t)QINT2BIG_32(*(qu32*)(buf + 1))) {
    fprintf(stderr, "invalid message length\n");
    return 1;
  }

  /* skip the 5 bytes grpc length-prefixed message */
  Qrl__GetBlockByNumberResp *pbblock_resp = qrl__get_block_by_number_resp__unpack(NULL, len - 5, (void*)buf + 5);
  assert(pbblock_resp != NULL);

  qblock_t *qblock = pbblock_to_qblock(pbblock_resp->block);
  assert(qblock != NULL);
  print_qblock(qblock, 0);

  hfunc_ctx hfunc;
  hfunc.hfunc = hfunc_cryptonight1;
  hfunc.digest_len = 32;
  /* we passed a valid block, it must be reported as valid */
  if (qrl_verify_qblock(qblock, &hfunc)) {
    fprintf(stderr, COLSTR("invalid block\n", BHRED));
  }

  /* flip the bits. we passed an invalid block, it must be reported as
   * invalid */
  qblock->block_hdr.hash_hdr.data[0] = ~qblock->block_hdr.hash_hdr.data[0];
  if (!qrl_verify_qblock(qblock, &hfunc)) {
    fprintf(stderr, COLSTR("uh-oh that was suppose to be an invalid block, yet it passed as valid\n", BHRED));
  }
  qblock->block_hdr.hash_hdr.data[0] = ~qblock->block_hdr.hash_hdr.data[0];

  int transfer_flipped = 0;
  for (size_t i = 0; i < qblock->nb_txs; i++) {
    if (qblock->txs[i].tx_type == QTX_TRANSFER) {
      qblock->txs[i].signature.data[0] = ~qblock->txs[i].signature.data[0];
      transfer_flipped = 1;
      break;
    }
  }

  if (transfer_flipped && !qrl_verify_qblock(qblock, &hfunc)) {
    fprintf(stderr, COLSTR("uh-oh that was suppose to be an invalid block, yet it passed as valid\n", BHRED));
  }

  qrl__get_block_by_number_resp__free_unpacked(pbblock_resp, NULL);
  free_qblock(*qblock);
  free(qblock);
  return 0;
}
