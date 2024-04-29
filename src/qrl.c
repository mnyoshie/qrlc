#include "randomx/randomx.h"
#include <stdio.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"
#include "hash.h"
#include "chain.h"

#include "include/types.h"

#include "dev_config.h"
//#include "include/qrl.pb-c.h"

#ifdef NDEBUG
#  error "Don't turn NDEBUG!"
#endif

#include <assert.h>


extern int qrl_gen_keypair(int);
extern int qrl_verify_sig(qvec_t pkey, qvec_t msg, qvec_t sig);


/* clang-format off */
/* computes hash header and writes 32 bytes to hash_header */
void qrl_compute_hash_header(const qblock_hdr_t block_header,
                             qvec_t hash_header, qvec_t seed_hash) {
  assert(hash_header.data != NULL);
  assert(seed_hash.len == 32);
  struct inctr_t ctr = {0};
  size_t sincr = 8;

  /* PHASE 1 */
  /* unsafe memory magic */
  uint8_t blob1[8 + 8 + 32 + 8 + 8 + 32] = {0};

  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_header.block_number)}, sincr);
  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_header.timestamp)}, sincr);
  sincr = 32;
  memcpy(blob1 + incrementp(&ctr, sincr), block_header.pheader_hash.data, sincr);
  sincr = 8;
  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_header.block_reward)}, sincr);
  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_header.fee_reward)}, sincr);
  sincr = 32;
  memcpy(blob1 + incrementp(&ctr, sincr), block_header.merkle_root.data, sincr);

  uint8_t blob1_md[58] = {0};
  qrl_shake128((qvec_t){58, blob1_md}, (qvec_t){ctr.i, blob1});

  /* PHASE 2 */
  uint8_t blob2[1 + 58] = {0};
  memcpy(blob2 + 1, blob1_md, 58);

  uint8_t mining_nonce_bytes[17] = {0};
  memcpy(mining_nonce_bytes,
         &(uint32_t){QBSWAP32(block_header.mining_nonce)}, 4);
  memcpy(mining_nonce_bytes + 4,
         &(uint64_t){QINT2BIG_64(block_header.extra_nonce)}, 8);

  /* mining nonce offset = 39 */
  /* 76 -18  = 58*/
  const int mining_nonce_offset = QRL_BLOCK_MINING_NONCE_OFFSET;

  /* JUST...... WHY? */
  /* mining_blob_final = mining_blob_final[:nonce_offset] + mining_nonce_bytes +
   * mining_blob_final[nonce_offset:] */
  uint8_t mining_blob_final[76] = {0};
  memcpy(mining_blob_final, blob2, mining_nonce_offset);
  memcpy(mining_blob_final + mining_nonce_offset, mining_nonce_bytes, 17);
  memcpy(mining_blob_final + mining_nonce_offset + 17,
         blob2 + mining_nonce_offset, 59 - mining_nonce_offset);

  if (block_header.block_number > QRL_HARD_FORK_HEIGHT0) {
//    unsigned char seed_hash[] = {
//        0xd0, 0xd1, 0xc4, 0xc6, 0x77, 0xf0, 0x5f, 0xe4, 0x29, 0x72, 0x7a,
//        0x49, 0xfa, 0x6e, 0xd0, 0x8c, 0xff, 0x03, 0x4c, 0xdd, 0x47, 0x5d,
//        0x7d, 0xbf, 0xe9, 0x79, 0x27, 0x14, 0x0a, 0x00, 0x00, 0x00};

    randomx_flags flags = randomx_get_flags();
    randomx_cache *myCache = randomx_alloc_cache(flags);
    randomx_init_cache(myCache, seed_hash.data, seed_hash.len);
    randomx_vm *myMachine = randomx_create_vm(flags, myCache, NULL);

    char hash[RANDOMX_HASH_SIZE] = {0};

    randomx_calculate_hash(myMachine, mining_blob_final, 76, hash);

    /* maybe in a future where randomx was updated */
    if (hash_header.len > RANDOMX_HASH_SIZE)
      memcpy(hash_header.data, hash, RANDOMX_HASH_SIZE);
    else
      memcpy(hash_header.data, hash, hash_header.len);

    randomx_destroy_vm(myMachine);
    randomx_release_cache(myCache);
  } else
    assert(0);
}

void qrl_compute_transaction_hash(qtx_t transaction,
                                  qvec_t transaction_hash) {
  struct inctr_t ctr = {0};
  size_t sincr = 0;
  switch (transaction.tx_type) {
    case QTX_TRANSFER: {
      if (transaction.transfer.n_amounts != transaction.transfer.n_addrs_to) {
        QRL_LOG_EX(QRL_LOG_ERROR,
                   "malformed transaction. %d (n_addrs) != %d (n_ammounts)\n",
                   transaction.transfer.n_addrs_to,
                   transaction.transfer.n_amounts);
      }

      size_t data_blob_len = transaction.master_addr.len +
                             sizeof(transaction.fee) +
                             transaction.transfer.message_data.len;

      // tmptxhash = (self.master_addr +
      //                      self.fee.to_bytes(8, byteorder='big',
      //                      signed=False) + self.message_data) for index in
      //                      range(0, len(self.addrs_to)): tmptxhash =
      //                      (tmptxhash +
      //                          self.addrs_to[index] +
      //                          self.amounts[index].to_bytes(8,
      //                          byteorder='big', signed=False))
      //
      //         return tmptxhash
      for (size_t i = 0; i < transaction.transfer.n_addrs_to; i++)
        data_blob_len += transaction.transfer.addrs_to[i].len +
                         sizeof(transaction.transfer.amounts[i]);

      uint8_t *data_blob = malloc(data_blob_len);

      assert(data_blob != NULL);

      sincr = transaction.master_addr.len;
      memcpy(data_blob + incrementp(&ctr, sincr), transaction.master_addr.data, sincr);
      sincr = sizeof(uint64_t);
      memcpy(data_blob + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(transaction.fee)}, sincr);
      sincr = transaction.transfer.message_data.len;
      memcpy(data_blob + incrementp(&ctr, sincr), transaction.transfer.message_data.data, sincr);

      do {
        size_t seek = ctr.i;

        for (qu32 i = 0; i < transaction.transfer.n_addrs_to; i++) {
          memcpy(data_blob + seek, transaction.transfer.addrs_to[i].data,
                 transaction.transfer.addrs_to[i].len);
          seek += transaction.transfer.addrs_to[i].len;
          memcpy(data_blob + seek,
                 &(uint64_t){QINT2BIG_64(transaction.transfer.amounts[i])},
                 sizeof(transaction.transfer.amounts[i]));
          seek += sizeof(transaction.transfer.amounts[i]);
        }
        assert(seek == data_blob_len);
      } while (0);

      uint8_t data_hash[32];
      qrl_sha256(data_blob, data_blob_len, data_hash);
      free(data_blob);

      QRL_LOG("data hash: ");
      qrl_printx(data_hash, 32);
      if (qrl_verify_sig(
              (qvec_t){.len=transaction.public_key.len, .data=transaction.public_key.data}, //
              (qvec_t){.len=32, .data=data_hash},         //
              (qvec_t){.len=transaction.signature.len, .data=transaction.signature.data})) {
        QRL_LOG_EX(QRL_LOG_ERROR, "invalid signature\n");
      }

      /* transaction blob: data_hash + sig + epkey */
      size_t transaction_blob_len =
          32 + transaction.signature.len + transaction.public_key.len;
      uint8_t *transaction_blob = malloc(transaction_blob_len);
      assert(transaction_blob != NULL);
      memcpy(transaction_blob, data_hash, 32);
      memcpy(transaction_blob + 32, transaction.signature.data, transaction.signature.len);
      memcpy(transaction_blob + 32 + transaction.signature.len, transaction.public_key.data, transaction.public_key.len);

      assert(transaction_hash.len >= 32);
      qrl_sha256(transaction_blob, transaction_blob_len, transaction_hash.data);
      QRL_LOG("computed transaction hash\n");
      qrl_dump(transaction_hash.data, transaction_hash.len);

      QRL_LOG("transaction transaction hash %d bytes\n",
              transaction.transaction_hash.len);
      qrl_dump(transaction.transaction_hash.data,
               transaction.transaction_hash.len);
      assert(transaction.transaction_hash.len == 32);

      if (memcmp(transaction_hash.data, transaction.transaction_hash.data, 32)) {
        QRL_LOG_EX(QRL_LOG_ERROR, "invalid transaction hash");
        return;
      }

      QRL_LOG("transaction pubkey %d bytes\n", transaction.public_key.len);
      qrl_dump(transaction.public_key.data, transaction.public_key.len);
      QRL_LOG("transaction signature %d bytes\n", transaction.signature.len);
      qrl_dump(transaction.signature.data, transaction.signature.len);
      break;
    }
    case QTX_COINBASE: {
      size_t transaction_blob_len =
          transaction.master_addr.len + transaction.coinbase.addr_to.len +
          sizeof(transaction.nonce) + sizeof(transaction.coinbase.amount);
      char *transaction_blob = malloc(transaction_blob_len);
      assert(transaction_blob != NULL);
      memcpy(transaction_blob, transaction.master_addr.data, transaction.master_addr.len);
      memcpy(transaction_blob + transaction.master_addr.len, transaction.coinbase.addr_to.data, transaction.coinbase.addr_to.len);
      memcpy(transaction_blob + transaction.master_addr.len + transaction.coinbase.addr_to.len,
             &(uint64_t){QINT2BIG_64(transaction.nonce)},
             sizeof(transaction.nonce));
      memcpy(transaction_blob + transaction.master_addr.len + transaction.coinbase.addr_to.len + sizeof(transaction.nonce),
             &(uint64_t){QINT2BIG_64(transaction.coinbase.amount)},
             sizeof(transaction.coinbase.amount));
      assert(transaction_hash.len >= 32);
      qrl_sha256(transaction_blob, transaction_blob_len, transaction_hash.data);
      QRL_LOG("transaction_hash coinbase: \n");
      qrl_dump(transaction_hash.data, transaction_hash.len);
      free(transaction_blob);
      break;
    }
    case QTX_LATTICEPK:
    case QTX_MESSAGE:
    case QTX_TOKEN:
    case QTX_TRANSFER_TOKEN:
    case QTX_SLAVE:
    case QTX_MULTISIG_CREATE:
    case QTX_MULTISIG_SPEND:
    case QTX_MULTISIG_VOTE:
    case QTX_PROPOSAL_CREATE:
    case QTX_PROPOSAL_VOTE:

    default:
      assert(0);
  }

  return;
}
/* clang-format on */

/* checks if QRL address is valid. returns nonzero if invalid */
int qrl_validate_address(uint8_t *addr, size_t len) {
  if (len < 39) {
    QRL_LOG_EX(QRL_LOG_ERROR, "invalid QRL address length: %d\n", len);
    return 1;
  }

  /* QRL address descriptor layout (24 bits). */
  /*------------------------------------------------\
  |  4 bits |  4 bits  | 4 bits |  4 bits  | 8 bits |
  |    SIG  |     HF   |   AF   |    P1    |   P2   |
  \-------------------------------------------------*/
  /* 23 bit <-------------------------------- 0 bit */

  /* SIG - Signature type */
  switch ((addr[0] >> 4) & 0x0f) {
    case 0:
      QRL_LOG_EX(QRL_LOG_VERBOSE, "signature type: XMSS\n");
      break;
    default:
      QRL_LOG_EX(QRL_LOG_ERROR, "unknown signature type %d\n",
                 (addr[0] >> 4) & 0x0f);
      return 1;
  }

  /* HF - Hash function */
  switch (addr[0] & 0x0f) {
    case 0:
      QRL_LOG_EX(QRL_LOG_VERBOSE, "address hash function: SHA2-256\n");
      break;
    case 1:
      QRL_LOG_EX(QRL_LOG_VERBOSE, "address hash function: SHAKE-128\n");
      break;
    case 2:
      QRL_LOG_EX(QRL_LOG_VERBOSE, "address hash function: SHAKE-256\n");
      break;
    default:
      QRL_LOG_EX(QRL_LOG_ERROR, "unknown address hash function %d\n",
                 addr[2] & 0x0f);
      return 1;
  }
  /* AF  Address format */
  switch ((addr[1] >> 4) & 0x0f) {
    case 0:
      QRL_LOG_EX(QRL_LOG_VERBOSE, "address format: SHA256_2X\n");
      break;
    default:
      QRL_LOG_EX(QRL_LOG_ERROR, "unknown signature type %d\n",
                 (addr[1] >> 4) & 0x0f);
      return 1;
  }
  switch (addr[1] & 0x0f) {
    case 0:
      QRL_LOG_EX(QRL_LOG_VERBOSE, "address height\n");
      break;
    default:
      QRL_LOG_EX(QRL_LOG_ERROR, "unknown signature type %d\n",
                 (addr[1] >> 4) & 0x0f);
      return 1;
  }
  return 0;
}

volatile int current_height = 0;
int main() {
  qrl_log_level = ~0 & ~QRL_LOG_TRACE;
    unsigned char seed_hash[] = {
        0xd0, 0xd1, 0xc4, 0xc6, 0x77, 0xf0, 0x5f, 0xe4, 0x29, 0x72, 0x7a,
        0x49, 0xfa, 0x6e, 0xd0, 0x8c, 0xff, 0x03, 0x4c, 0xdd, 0x47, 0x5d,
        0x7d, 0xbf, 0xe9, 0x79, 0x27, 0x14, 0x0a, 0x00, 0x00, 0x00};


  qchain_t *chain = qrl_open_chain("/storage/6366-6331/Android/data/com.termux/files/qrl/state");

  for (qu64 i = 0; i < 10; i++)
    qblock_t *qblock1 = qrl_get_block_by_number(chain, i);
  qrl_close_chain(chain);

/*
  Qrl__GetBlockByNumberReq req = QRL__GET_BLOCK_BY_NUMBER_REQ__INIT;
  req.block_number = 0;// 2884686;
  Qrl__GetBlockByNumberResp *resp = qrl_get_block_by_number(req);
  assert(resp != NULL);
  QRL_LOG("block_number %" PRIu64 "\n", resp->block->header->block_number);*/

  //  uint8_t hash_header[32];
  //  qrl_compute_hash_header(*(resp->block->header), hash_header, 32);
  //  QRL_LOG("block_number %" PRIu64 "\n", resp->block->header->block_number);
  //  QRL_LOG("received hash header: \n");
  //  qrl_dump((void *)resp->block->header->hash_header.data, 32);
  //
  //  QRL_LOG("computed hash header: \n");
  //  qrl_dump((void *)hash_header, 32);
  /*
    uint8_t transaction_hash[32] = {0};
    qrl_compute_transaction_hash(*(resp->block->transactions)[2],
    transaction_hash, 32); qrl__get_block_by_number_resp__free_unpacked(resp,
    NULL);*/


  //qrl_gen_keypair(0x020500);
  return 0;
}
