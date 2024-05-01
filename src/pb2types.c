/* pb2types.c - protobuf serialized data to internal types conversion and vice
 * versa. Translator
 *
 * To deal with portability issues arising from future modification to qrl.proto
 *
 */

#include "pb2types.h"

static qvec_t pbvec_to_qvec(ProtobufCBinaryData pbvec) {
  void *data = malloc(pbvec.len);
  size_t len = pbvec.len;
  assert(data != NULL);
  memcpy(data, pbvec.data, pbvec.len);

  return (qvec_t){.data=data, .len=len};
}

static ProtobufCBinaryData qvec_to_pbvec(qvec_t qvec) {
  void *data = malloc(qvec.len);
  size_t len = qvec.len;
  assert(data != NULL);
  memcpy(data, qvec.data, qvec.len);

  return (ProtobufCBinaryData){.data=data, .len=len};
}

qvec_t qblock_pack(const qblock_t *qblock) {
  void *data;
  size_t len;
  Qrl__Block *pbblock = malloc(sizeof(*pbblock));
  assert(pbblock != NULL);
  qrl__block__init(pbblock);

  pbblock->header = malloc(sizeof(*pbblock->header));
  assert(pbblock->header != NULL);
  qrl__block_header__init(pbblock->header);

  /* clang-format off */
  /**************BLOCK HEADER***************************/
  pbblock->header->hash_header        = qvec_to_pbvec(qblock->block_hdr.hash_hdr);
  pbblock->header->block_number       =               qblock->block_hdr.block_number;
  pbblock->header->timestamp_seconds  =               qblock->block_hdr.timestamp;    
  pbblock->header->hash_header_prev   = qvec_to_pbvec(qblock->block_hdr.hash_phdr); 
  pbblock->header->reward_block       =               qblock->block_hdr.reward_block; 
  pbblock->header->reward_fee         =               qblock->block_hdr.reward_fee;   
  pbblock->header->merkle_root        = qvec_to_pbvec(qblock->block_hdr.merkle_root); 
  pbblock->header->mining_nonce       =               qblock->block_hdr.mining_nonce; 
  pbblock->header->extra_nonce        =               qblock->block_hdr.extra_nonce;

  /**************TRANSACTIONS***************************/

  pbblock->n_transactions = qblock->nb_txs;
  pbblock->transactions = malloc(sizeof(*pbblock->transactions));
  assert(pbblock->transactions != NULL);
  (*pbblock->transactions) = malloc(sizeof(**pbblock->transactions)*qblock->nb_txs);
  assert(*pbblock->transactions != NULL);

  for (qu64 i = 0; i < qblock->nb_txs; i++) {
    qrl__transaction__init((*pbblock->transactions) + i);
    (*pbblock->transactions)[i].transaction_type_case =               qblock->txs[i].tx_type;
    (*pbblock->transactions)[i].master_addr           = qvec_to_pbvec(qblock->txs[i].master_addr);
    (*pbblock->transactions)[i].fee                   =               qblock->txs[i].fee;
    (*pbblock->transactions)[i].public_key            = qvec_to_pbvec(qblock->txs[i].public_key);
    (*pbblock->transactions)[i].signature             = qvec_to_pbvec(qblock->txs[i].signature);
    (*pbblock->transactions)[i].nonce                 =               qblock->txs[i].nonce;
    (*pbblock->transactions)[i].transaction_hash      = qvec_to_pbvec(qblock->txs[i].transaction_hash);
  }
  /* clang-format on */
  len = qrl__block__get_packed_size(pbblock);
  data = malloc(len);
  assert(data != NULL);
  len = qrl__block__pack(pbblock, data);

  qrl__block__free_unpacked(pbblock, NULL);
  return (qvec_t){.data=data, .len=len};
}

qblock_t *qblock_unpack(const qvec_t *block) {
  Qrl__Block *pbblock = qrl__block__unpack(NULL, block->len, block->data);
  assert(pbblock != NULL);
  qblock_t *qblock = malloc(sizeof(*qblock));
  assert(qblock != NULL);

  /* clang-format off */
  /**************BLOCK HEADER***************************/
  qblock->block_hdr.hash_hdr     = pbvec_to_qvec(pbblock->header->hash_header);
  qblock->block_hdr.block_number =               pbblock->header->block_number;
  qblock->block_hdr.timestamp    =               pbblock->header->timestamp_seconds;
  qblock->block_hdr.hash_phdr    = pbvec_to_qvec(pbblock->header->hash_header_prev);
  qblock->block_hdr.reward_block =               pbblock->header->reward_block;
  qblock->block_hdr.reward_fee   =               pbblock->header->reward_fee;
  qblock->block_hdr.merkle_root  = pbvec_to_qvec(pbblock->header->merkle_root);
  qblock->block_hdr.mining_nonce =               pbblock->header->mining_nonce;
  qblock->block_hdr.extra_nonce  =               pbblock->header->extra_nonce;

  /**************TRANSACTIONS***************************/
  qblock->nb_txs = pbblock->n_transactions;
  qblock->txs = malloc(sizeof(*qblock->txs)*qblock->nb_txs);
  assert(qblock->txs != NULL);
  for (size_t i = 0; i < qblock->nb_txs; i++) {
    qblock->txs[i].tx_type          =               (*pbblock->transactions)[i].transaction_type_case;
    qblock->txs[i].master_addr      = pbvec_to_qvec((*pbblock->transactions)[i].master_addr);
    qblock->txs[i].fee              =               (*pbblock->transactions)[i].fee;
    qblock->txs[i].public_key       = pbvec_to_qvec((*pbblock->transactions)[i].public_key);
    qblock->txs[i].signature        = pbvec_to_qvec((*pbblock->transactions)[i].signature);
    qblock->txs[i].nonce            =               (*pbblock->transactions)[i].nonce;
    qblock->txs[i].transaction_hash = pbvec_to_qvec((*pbblock->transactions)[i].transaction_hash);

    switch (qblock->txs[i].tx_type) {
      case QTX_TRANSFER:

        qblock->txs[i].transfer.n_addrs_to   =                (*pbblock->transactions)[i].transfer->n_addrs_to;
        for (size_t t = 0; i < qblock->txs[i].transfer.n_addrs_to; i++)
          qblock->txs[i].transfer.addrs_to[t] = pbvec_to_qvec((*pbblock->transactions)[i].transfer->addrs_to[t]);

        qblock->txs[i].transfer.n_amounts    =                (*pbblock->transactions)[i].transfer->n_amounts;
        for (size_t t = 0; t < qblock->txs[i].transfer.n_amounts; i++)
          qblock->txs[i].transfer.amounts[t] =                (*pbblock->transactions)[i].transfer->amounts[t];

        qblock->txs[i].transfer.message_data = pbvec_to_qvec((*pbblock->transactions)[i].transfer->message_data);
        assert(qblock->txs[i].transfer.n_addrs_to == qblock->txs[i].transfer.n_amounts);
        break;

      case QTX_COINBASE:
        qblock->txs[i].coinbase.amount   =               (*pbblock->transactions)[i].coinbase->amount;
        qblock->txs[i].coinbase.addr_to  = pbvec_to_qvec((*pbblock->transactions)[i].coinbase->addr_to);
        break;
      default: QRL_LOG_EX(QRL_LOG_ERROR, "unknown transaction type %d\n",qblock->txs[i].tx_type);  assert(0);
    }
  }


  /* clang-format on */

  qrl__block__free_unpacked(pbblock, NULL);

  return qblock;
}

//Qrl__Transaction **txt_pbtx(const qtx_t *tx){
//  Qrl__Transaction **msg = malloc(sizeof(*msg));
//  assert(msg != NULL);
//  Qrl__Transaction *msgtxs = malloc(sizeof(*msg)*tx->nb_txs);
//  assert(msgtxs != NULL);
//
//  for (size_t i = 0; i < tx->nb_txs; i++) {
//    (msgtxs + i)->
//  }
//
//  *msg = msgtxs;
//  return msg;
//}
//
//Qrl__Block *blockt_pbblock(const qblock_t *block){
//  Qrl__Block *msg;
//
//  msg = malloc(sizeof(*msg));
//  assert(msg != NULL);
//  qrl__block__init(msg); 
//
//  msg->header = blockhdrt_pbblockhdr(block->hdr);
//  msg->n_transactions = block->nb_txs
//  msg->transactions = txt_pbtx(block->txs);
//
//  return msg;
//}
//
//qvec_t blockt_pbblock_sr(const qblock_t *block){
//  void *data;
//  size_t len;
//
//  Qrl__Block *msg = blockt_pbblock(block);
//  assert(msg != NULL);
//  len = qrl__block__get_packed_size(msg)
//  data = malloc(len);
//  assert(data != NULL);
//  len = qrl__block__pack(msg, data);
//
//  return (qvec_t){.data=data, .len=len};
//}
