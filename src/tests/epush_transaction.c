#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <qrl.pb-c.h>

#include "utils.h"
#include "xmss.h"
#include "pb2types.h"
#include "include/types.h"

extern qvec_t qrl_compute_qtx_transfer_hash(const qtx_t *);

int main(int argc, char *argv[]) {
  uint8_t seed_c1[] = {0x00, 0x04, 0x00, 0x91, 0xa2, 0x44, 0x64, 0x5d, 0x1c,
                       0x16, 0xda, 0x90, 0xe9, 0x36, 0x3e, 0x71, 0xf8, 0x42,
                       0x04, 0x8f, 0xfa, 0x9b, 0xf6, 0x9a, 0x8b, 0x1a, 0xea,
                       0xe3, 0x6f, 0x6d, 0xcd, 0xa8, 0xab, 0xfa, 0x8e, 0xc3,
                       0x1e, 0x3a, 0xd5, 0xee, 0x7e, 0xe6, 0xe3, 0x8a, 0xf7,
                       0xae, 0x95, 0xd4, 0xcc, 0x41, 0x36};


  size_t len;
  void *out;
  Qrl__PushTransactionReq pb;
  qrl__push_transaction_req__init(&pb);

  qvec_t seed1 = {.data = (void*)seed_c1, .len = 51};

  qvec_t pub_key1 = xmss_gen_pubkey(seed1);

  qvec_t pub_addr1 = xmss_pubkey_to_pubaddr(pub_key1);
  qvec_t pub_addr2 = qrl_qveccpy(pub_addr1);

  qtx_t qtx;
  qtx.tx_type = QTX_TRANSFER;
  qtx.master_addr = qrl_qveccpy(pub_addr1); 
  qtx.signature = qrl_qvecmalloc(1024);
  qtx.public_key = qrl_qveccpy(pub_key1);
  qtx.fee = 100000;
  qtx.nonce = 0;
  qtx.transfer.message_data = QVEC_NULL;
  qtx.transfer.nb_transfer_to = 1;
  qtx.transfer.amounts = &(qu64){3090001};
  qtx.transfer.addrs_to = (qvec_t[]){qrl_qveccpy(pub_addr2)};
  qtx.tx_hash = qrl_compute_qtx_transfer_hash(&qtx);
  pb.transaction_signed = qtx_to_pbtx(&qtx);


  len = qrl__push_transaction_req__get_packed_size(&pb);
  out = malloc(len);
  len = qrl__push_transaction_req__pack(&pb, out);

  /* uncompressed */
  write(1, &(char){0}, 1);
  /* protobuf message length */
  write(1, &(qu32){QINT2BIG_32((qu32)len)}, 4);
  /* the actual message */
  write(1, out, len);
  free(out);
  qrl_qvecfree(pub_addr1);
  qrl_qvecfree(pub_key1);
  free_qtx(qtx);
  return 0;
}
