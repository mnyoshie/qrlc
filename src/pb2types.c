/* pb2types.c - protobuf serialized data to internal types conversion and vice
 * versa. Translator
 *
 * To deal with portability issues arising from future modification to qrl.proto
 *
 */

#include <stdlib.h>
#include <assert.h>
#include "log.h"
#include "utils.h"
#include "pb2types.h"

#define NOOP(x) (x)

static qvec_t pbvec_to_qvec(ProtobufCBinaryData pbvec) {
  if (pbvec.len == 0)
    return QVEC_NULL;
  void *data = malloc(pbvec.len);
  size_t len = pbvec.len;
  assert(data != NULL);
  memcpy(data, pbvec.data, pbvec.len);

  return (qvec_t){.data=data, .len=len};
}

static ProtobufCBinaryData qvec_to_pbvec(qvec_t qvec) {
  if (qvec.len == 0)
    return (ProtobufCBinaryData){.data=NULL, .len=0};
  void *data = malloc(qvec.len);
  size_t len = qvec.len;
  assert(data != NULL);
  memcpy(data, qvec.data, qvec.len);

  return (ProtobufCBinaryData){.data=data, .len=len};
}



/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////


qblock_t *pbblock_to_qblock(Qrl__Block *pbblock) {
  int err = 0;
  qblock_t *qblock = calloc(1, sizeof(*qblock));
  assert(qblock != NULL);

  /* clang-format off */
  /**************BLOCK HEADER***************************/
  qblock->block_hdr.hash_hdr     = pbvec_to_qvec(pbblock->header->hash_header);
  qblock->block_hdr.block_number =          NOOP(pbblock->header->block_number);
  qblock->block_hdr.timestamp    =          NOOP(pbblock->header->timestamp_seconds);
  qblock->block_hdr.hash_phdr    = pbvec_to_qvec(pbblock->header->hash_header_prev);
  qblock->block_hdr.reward_block =          NOOP(pbblock->header->reward_block);
  qblock->block_hdr.reward_fee   =          NOOP(pbblock->header->reward_fee);
  qblock->block_hdr.merkle_root  = pbvec_to_qvec(pbblock->header->merkle_root);
  qblock->block_hdr.mining_nonce =          NOOP(pbblock->header->mining_nonce);
  qblock->block_hdr.extra_nonce  =          NOOP(pbblock->header->extra_nonce);

  /**************TRANSACTIONS***************************/
  qblock->nb_txs =   NOOP(pbblock->n_transactions);
  qblock->txs = malloc(sizeof(*qblock->txs)*qblock->nb_txs);
  assert(qblock->txs != NULL);
  for (size_t i = 0; i < qblock->nb_txs; i++) {
    qblock->txs[i].tx_type          =   (qtx_type_t)pbblock->transactions[i]->transaction_type_case;
    qblock->txs[i].master_addr      = pbvec_to_qvec(pbblock->transactions[i]->master_addr);
    qblock->txs[i].fee              =          NOOP(pbblock->transactions[i]->fee);
    qblock->txs[i].public_key       = pbvec_to_qvec(pbblock->transactions[i]->public_key);
    qblock->txs[i].signature        = pbvec_to_qvec(pbblock->transactions[i]->signature);
    qblock->txs[i].nonce            =          NOOP(pbblock->transactions[i]->nonce);
    qblock->txs[i].tx_hash          = pbvec_to_qvec(pbblock->transactions[i]->transaction_hash);

    switch (qblock->txs[i].tx_type) {
      case QTX_TRANSFER:
        if (pbblock->transactions[i]->transfer->n_addrs_to != pbblock->transactions[i]->transfer->n_amounts) {
          QLOGX(QLOG_ERROR, "invalid block while unpacking, n_addrs_to != n_amounts\n");
          qblock->nb_txs = i + 1;
          err = 0xff;
          goto exit;
        }

        qblock->txs[i].transfer.nb_transfer_to =            NOOP(
            pbblock->transactions[i]->transfer->n_addrs_to &
            pbblock->transactions[i]->transfer->n_amounts
        );
        qblock->txs[i].transfer.addrs_to       =       malloc(sizeof(qvec_t)*qblock->txs[i].transfer.nb_transfer_to);
        qblock->txs[i].transfer.amounts        =       malloc(sizeof(qu64)*qblock->txs[i].transfer.nb_transfer_to);
        for (size_t t = 0; t < qblock->txs[i].transfer.nb_transfer_to; t++) {
          qblock->txs[i].transfer.addrs_to[t]  = pbvec_to_qvec(pbblock->transactions[i]->transfer->addrs_to[t]);
          qblock->txs[i].transfer.amounts[t]   =            NOOP(pbblock->transactions[i]->transfer->amounts[t]);
        }

        qblock->txs[i].transfer.message_data   =   pbvec_to_qvec(pbblock->transactions[i]->transfer->message_data);
        break;

      case QTX_COINBASE:
        qblock->txs[i].coinbase.amount         =            NOOP(pbblock->transactions[i]->coinbase->amount);
        qblock->txs[i].coinbase.addr_to        =   pbvec_to_qvec(pbblock->transactions[i]->coinbase->addr_to);
        break;
      case QTX_MESSAGE:
        qblock->txs[i].message.message_hash    =   pbvec_to_qvec(pbblock->transactions[i]->message->message_hash); 
        qblock->txs[i].message.addr_to         =   pbvec_to_qvec(pbblock->transactions[i]->message->addr_to);
        break;
      case QTX_LATTICEPK:
        qblock->txs[i].latticepk.pk1           =   pbvec_to_qvec(pbblock->transactions[i]->latticepk->pk1);
        qblock->txs[i].latticepk.pk2           =   pbvec_to_qvec(pbblock->transactions[i]->latticepk->pk2);
        qblock->txs[i].latticepk.pk3           =   pbvec_to_qvec(pbblock->transactions[i]->latticepk->pk3);
        break;
      default:
        QLOGX(QLOG_ERROR, "unknown transaction type %d\n",qblock->txs[i].tx_type);
        qblock->txs[i].tx_type = QTX_UNKNOWN;
        err = 0xff;
        break;
    }
  }

exit:
  if (err) {
    free_qblock(*qblock);
    free(qblock);
    qblock = NULL;
  }

  return qblock;
}

Qrl__Transaction *qtx_to_pbtx(const qtx_t *qtx) {
  Qrl__Transaction *pbtx = malloc(sizeof(*pbtx));
  assert(pbtx != NULL);
  qrl__transaction__init(pbtx);

  pbtx->transaction_type_case = (Qrl__Transaction__TransactionTypeCase)qtx->tx_type;
  pbtx->master_addr           = qvec_to_pbvec(qtx->master_addr);
  pbtx->fee                   =          NOOP(qtx->fee);
  pbtx->public_key            = qvec_to_pbvec(qtx->public_key);
  pbtx->signature             = qvec_to_pbvec(qtx->signature);
  pbtx->nonce                 =          NOOP(qtx->nonce);
  pbtx->transaction_hash      = qvec_to_pbvec(qtx->tx_hash);
  switch (pbtx->transaction_type_case) {
    case QRL__TRANSACTION__TRANSACTION_TYPE_TRANSFER:
      pbtx->transfer                 =  malloc(sizeof(*pbtx->transfer));
      qrl__transaction__transfer__init(pbtx->transfer);

      pbtx->transfer->n_addrs_to     =  qtx->transfer.nb_transfer_to;
      pbtx->transfer->n_amounts      =  qtx->transfer.nb_transfer_to;
      pbtx->transfer->addrs_to       =  malloc(sizeof(ProtobufCBinaryData)*pbtx->transfer->n_addrs_to);
      pbtx->transfer->amounts        =  malloc(sizeof(uint64_t)*pbtx->transfer->n_amounts);
      for (size_t t = 0; t < qtx->transfer.nb_transfer_to; t++) {
        //printf("tx %zu\n", t);
        //qtx->transfer.addrs_to[t] = pbvec_to_qvec((*(pbtx)).transfer->addrs_to[t]);
        pbtx->transfer->addrs_to[t]  = qvec_to_pbvec(qtx->transfer.addrs_to[t]);
        pbtx->transfer->amounts[t]   = qtx->transfer.amounts[t];
      }

      pbtx->transfer->message_data   = qvec_to_pbvec(qtx->transfer.message_data);
      break;
    case QRL__TRANSACTION__TRANSACTION_TYPE_COINBASE:
      pbtx->coinbase                 =  malloc(sizeof(*pbtx->coinbase));
      qrl__transaction__coin_base__init(pbtx->coinbase);

      pbtx->coinbase->amount         =                qtx->coinbase.amount;
      pbtx->coinbase->addr_to        =  qvec_to_pbvec(qtx->coinbase.addr_to);
      break;
    case QRL__TRANSACTION__TRANSACTION_TYPE_MESSAGE:
      pbtx->message                  =  malloc(sizeof(*pbtx->message));
      qrl__transaction__message__init(pbtx->message);

      pbtx->message->message_hash    =  qvec_to_pbvec(qtx->message.message_hash);
      pbtx->message->addr_to         =  qvec_to_pbvec(qtx->message.addr_to);
      break;
    case QRL__TRANSACTION__TRANSACTION_TYPE_LATTICE_PK:
      pbtx->latticepk                =  malloc(sizeof(*pbtx->latticepk));
      qrl__transaction__lattice_public_key__init(pbtx->latticepk);

      pbtx->latticepk->pk1           =  qvec_to_pbvec(qtx->latticepk.pk1);
      pbtx->latticepk->pk2           =  qvec_to_pbvec(qtx->latticepk.pk2);
      pbtx->latticepk->pk3           =  qvec_to_pbvec(qtx->latticepk.pk3);
      break;
    default: QLOGX(QLOG_ERROR, "unknown transaction type %d\n",pbtx->transaction_type_case);  assert(0);
  }
  return pbtx;
}

qvec_t pack_qtx(const qtx_t *qtx) {
  void *data;
  size_t len;
  Qrl__Transaction *pbtx = qtx_to_pbtx(qtx);
  len = qrl__transaction__get_packed_size(pbtx);
  data = malloc(len);
  assert(data != NULL);

  len = qrl__transaction__pack(pbtx, data);
  qrl__transaction__free_unpacked(pbtx, NULL);

  return (qvec_t){.data=data, .len=len};
}

qvec_t pack_qblock(const qblock_t *qblock) {
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
  pbblock->header->block_number       =          NOOP(qblock->block_hdr.block_number);
  pbblock->header->timestamp_seconds  =          NOOP(qblock->block_hdr.timestamp);    
  pbblock->header->hash_header_prev   = qvec_to_pbvec(qblock->block_hdr.hash_phdr); 
  pbblock->header->reward_block       =          NOOP(qblock->block_hdr.reward_block); 
  pbblock->header->reward_fee         =          NOOP(qblock->block_hdr.reward_fee);   
  pbblock->header->merkle_root        = qvec_to_pbvec(qblock->block_hdr.merkle_root); 
  pbblock->header->mining_nonce       =          NOOP(qblock->block_hdr.mining_nonce); 
  pbblock->header->extra_nonce        =          NOOP(qblock->block_hdr.extra_nonce);

  /**************TRANSACTIONS***************************/

  pbblock->n_transactions =        NOOP(qblock->nb_txs);
  pbblock->transactions = malloc(sizeof(*pbblock->transactions)*pbblock->n_transactions);
  assert(pbblock->transactions != NULL);

  for (qu64 i = 0; i < pbblock->n_transactions; i++) {
    pbblock->transactions[i] = qtx_to_pbtx(&qblock->txs[i]);
  }
  /* clang-format on */
  len = qrl__block__get_packed_size(pbblock);
  data = malloc(len);
  assert(data != NULL);
  len = qrl__block__pack(pbblock, data);

  qrl__block__free_unpacked(pbblock, NULL);
  return (qvec_t){.data=data, .len=len};
}



//////////



qblock_t *unpack_qblock(const qvec_t *block) {
  Qrl__Block *pbblock = qrl__block__unpack(NULL, block->len, block->data);
//  assert(pbblock != NULL);
  if (pbblock == NULL) {
    QLOGX(QLOG_ERROR, "invalid protobuf data\n");
    return NULL;
  }

  qblock_t *qblock = pbblock_to_qblock(pbblock);
  assert(qblock != NULL);
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
