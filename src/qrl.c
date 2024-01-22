#include <openssl/evp.h>
#include <openssl/sha.h>
#include <randomx.h>
#include <stdio.h>
#include <unistd.h>

#include "include/dev_config.h"
#include "include/log.h"
#include "include/qrl.pb-c.h"
#include "include/utils.h"

#ifdef NDEBUG
#  error "Don't turn NDEBUG!"
#endif

#include <assert.h>
extern Qrl__GetBlockByNumberResp *qrl_get_block_by_number(
    Qrl__GetBlockByNumberReq);
extern Qrl__GetHeightResp *qrl_get_height(Qrl__GetHeightReq request);
extern int qrl_gen_keypair(int);
extern int qrl_verify_sig(uint8_t *pkey, size_t pkey_len, uint8_t *msg,
                          size_t msg_len, uint8_t *sig, size_t sig_len);
extern int qrl_add_grpc_transfer(char *, ProtobufCBinaryData, void *,
                                 int *volatile);
extern int qrl_init_grpc();
extern void qrl_shutdown_grpc();
/*------------\
 * SHAKE-128  |
 *-----------*/
void qrl_shake128(const uint8_t *message, int message_len, uint8_t *digest,
                  int digest_len) {
  int status = 0;

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  assert(mdctx != NULL);
  if (EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  if (EVP_DigestUpdate(mdctx, message, message_len) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  if (EVP_DigestFinalXOF(mdctx, digest, digest_len) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  EVP_MD_CTX_free(mdctx);
}

/*------------\
 * SHAKE-256  |
 *-----------*/
void qrl_shake256(uint8_t *message, int message_len, uint8_t *digest,
                  int digest_len) {
  int status = 0;
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  assert(mdctx != NULL);
  if (EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL) != 1) {
    assert(0);
  }

  if (EVP_DigestUpdate(mdctx, message, message_len) != 1) {
    assert(0);
  }

  if (EVP_DigestFinalXOF(mdctx, digest, digest_len) != 1) {
    assert(0);
  }

  EVP_MD_CTX_free(mdctx);
}

/*------------\
 *  SHA-256   |
 *-----------*/
void qrl_sha256(const uint8_t *message, int message_len, uint8_t *digest) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  assert(mdctx != NULL);
  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
    assert(0);
  }

  if (EVP_DigestUpdate(mdctx, message, message_len) != 1) {
    assert(0);
  }

  uint8_t dg[EVP_MAX_MD_SIZE];
  unsigned int len;
  if (EVP_DigestFinal_ex(mdctx, digest, &len) != 1) {
    assert(0);
  }
  /* paranoid */
  assert(len == 32);

  EVP_MD_CTX_free(mdctx);
}

/* computes hash header and writes 32 bytes to hash_header */
void qrl_compute_hash_header(const Qrl__BlockHeader block_header,
                             uint8_t *hash_header, size_t hash_header_len) {
  assert(hash_header != NULL);

  /* PHASE 1 */
  /* unsafe memory magic */
  uint8_t blob1[8 + 8 + 32 + 8 + 8 + 32] = {0};

  /* I QRL stored this field in little endian in the protobuf but its not
   */
  memcpy(blob1 + 0, &(uint64_t){QRL_BSWAP64(block_header.block_number)}, 8);
  memcpy(blob1 + 8, &(uint64_t){QRL_BSWAP64(block_header.timestamp_seconds)},
         8);
  memcpy(blob1 + 8 + 8, block_header.hash_header_prev.data, 32);
  memcpy(blob1 + 8 + 8 + 32,
         &(uint64_t){QRL_BSWAP64(block_header.reward_block)}, 8);
  memcpy(blob1 + 8 + 8 + 32 + 8,
         &(uint64_t){QRL_BSWAP64(block_header.reward_fee)}, 8);
  memcpy(blob1 + 8 + 8 + 32 + 8 + 8, block_header.merkle_root.data, 32);

  uint8_t blob1_md[58] = {0};
  qrl_shake128(blob1, 8 + 8 + 32 + 8 + 8 + 32, blob1_md, 58);

  /* PHASE 2 */
  uint8_t blob2[1 + 58] = {0};
  memcpy(blob2 + 1, blob1_md, 58);

  uint8_t mining_nonce_bytes[17] = {0};
  memcpy(mining_nonce_bytes,
         &(uint32_t){QRL_BSWAP32(block_header.mining_nonce)}, 4);
  memcpy(mining_nonce_bytes + 4,
         &(uint64_t){QRL_BSWAP64(block_header.extra_nonce)}, 8);

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
    unsigned char seed_hash[] = {
        0xd0, 0xd1, 0xc4, 0xc6, 0x77, 0xf0, 0x5f, 0xe4, 0x29, 0x72, 0x7a,
        0x49, 0xfa, 0x6e, 0xd0, 0x8c, 0xff, 0x03, 0x4c, 0xdd, 0x47, 0x5d,
        0x7d, 0xbf, 0xe9, 0x79, 0x27, 0x14, 0x0a, 0x00, 0x00, 0x00};

    randomx_flags flags = randomx_get_flags();
    randomx_cache *myCache = randomx_alloc_cache(flags);
    randomx_init_cache(myCache, seed_hash, 32);
    randomx_vm *myMachine = randomx_create_vm(flags, myCache, NULL);

    char hash[RANDOMX_HASH_SIZE] = {0};

    randomx_calculate_hash(myMachine, mining_blob_final, 76, hash);

    /* maybe in a future where randomx was updated */
    if (hash_header_len > RANDOMX_HASH_SIZE)
      memcpy(hash_header, hash, RANDOMX_HASH_SIZE);
    else
      memcpy(hash_header, hash, hash_header_len);

    randomx_destroy_vm(myMachine);
    randomx_release_cache(myCache);
  } else
    assert(0);
}

void qrl_compute_transaction_hash(Qrl__Transaction transaction,
                                  uint8_t *transaction_hash,
                                  size_t transaction_hash_len) {
  switch (transaction.transaction_type_case) {
    case QRL__TRANSACTION__TRANSACTION_TYPE_TRANSFER: {
      if (transaction.transfer->n_amounts != transaction.transfer->n_addrs_to) {
        QRL_LOG_EX(QRL_LOG_ERROR,
                   "malformed transaction. %d (n_addrs) != %d (n_ammounts)\n",
                   transaction.transfer->n_addrs_to,
                   transaction.transfer->n_amounts);
      }

      size_t data_blob_len = transaction.master_addr.len +
                             sizeof(transaction.fee) +
                             transaction.transfer->message_data.len;

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
      for (size_t i = 0; i < transaction.transfer->n_addrs_to; i++)
        data_blob_len += transaction.transfer->addrs_to[i].len +
                         sizeof(transaction.transfer->amounts[i]);

      uint8_t *data_blob = malloc(data_blob_len);

      assert(data_blob != NULL);

      memcpy(data_blob, transaction.master_addr.data,
             transaction.master_addr.len);
      memcpy(data_blob + transaction.master_addr.len,
             &(uint64_t){QRL_BSWAP64(transaction.fee)}, sizeof(uint64_t));
      memcpy(data_blob + transaction.master_addr.len + sizeof(uint64_t),
             transaction.transfer->message_data.data,
             transaction.transfer->message_data.len);

      do {
        size_t seek = transaction.master_addr.len + sizeof(uint64_t) +
                      transaction.transfer->message_data.len;

        for (int i = 0; i < transaction.transfer->n_addrs_to; i++) {
          memcpy(data_blob + seek, transaction.transfer->addrs_to[i].data,
                 transaction.transfer->addrs_to[i].len);
          seek += transaction.transfer->addrs_to[i].len;
          memcpy(data_blob + seek,
                 &(uint64_t){QRL_BSWAP64(transaction.transfer->amounts[i])},
                 sizeof(transaction.transfer->amounts[i]));
          seek += sizeof(transaction.transfer->amounts[i]);
        }
        assert(seek == data_blob_len);
      } while (0);

      uint8_t data_hash[32];
      qrl_sha256(data_blob, data_blob_len, data_hash);
      free(data_blob);

      QRL_LOG("data hash: ");
      qrl_printx(data_hash, 32);
      if (qrl_verify_sig(
              transaction.public_key.data, transaction.public_key.len,
              data_hash,  //
              32,         //
              transaction.signature.data, transaction.signature.len)) {
        QRL_LOG_EX(QRL_LOG_ERROR, "invalid signature\n");
      }

      /* transaction blob: data_hash + sig + epkey */
      size_t transaction_blob_len =
          32 + transaction.signature.len + transaction.public_key.len;
      uint8_t *transaction_blob = malloc(transaction_blob_len);
      assert(transaction_blob != NULL);
      memcpy(transaction_blob, data_hash, 32);
      memcpy(transaction_blob + 32, transaction.signature.data,
             transaction.signature.len);
      memcpy(transaction_blob + 32 + transaction.signature.len,
             transaction.public_key.data, transaction.public_key.len);

      assert(transaction_hash_len >= 32);
      qrl_sha256(transaction_blob, transaction_blob_len, transaction_hash);
      QRL_LOG("computed transaction hash\n");
      qrl_dump(transaction_hash, 32);

      QRL_LOG("transaction transaction hash %d bytes\n",
              transaction.transaction_hash.len);
      qrl_dump(transaction.transaction_hash.data,
               transaction.transaction_hash.len);
      assert(transaction.transaction_hash.len == 32);

      if (memcmp(transaction_hash, transaction.transaction_hash.data, 32)) {
        QRL_LOG_EX(QRL_LOG_ERROR, "invalid transaction hash");
        return;
      }

      QRL_LOG("transaction pubkey %d bytes\n", transaction.public_key.len);
      qrl_dump(transaction.public_key.data, transaction.public_key.len);
      QRL_LOG("transaction signature %d bytes\n", transaction.signature.len);
      qrl_dump(transaction.signature.data, transaction.signature.len);
      break;
    }
    case QRL__TRANSACTION__TRANSACTION_TYPE_COINBASE: {
      size_t transaction_blob_len =
          transaction.master_addr.len + transaction.coinbase->addr_to.len +
          sizeof(transaction.nonce) + sizeof(transaction.coinbase->amount);
      char *transaction_blob = malloc(transaction_blob_len);
      assert(transaction_blob != NULL);
      memcpy(transaction_blob, transaction.master_addr.data,
             transaction.master_addr.len);
      memcpy(transaction_blob + transaction.master_addr.len,
             transaction.coinbase->addr_to.data,
             transaction.coinbase->addr_to.len);
      memcpy(transaction_blob + transaction.master_addr.len +
                 transaction.coinbase->addr_to.len,
             &(uint64_t){QRL_BSWAP64(transaction.nonce)},
             sizeof(transaction.nonce));
      memcpy(transaction_blob + transaction.master_addr.len +
                 transaction.coinbase->addr_to.len + sizeof(transaction.nonce),
             &(uint64_t){QRL_BSWAP64(transaction.coinbase->amount)},
             sizeof(transaction.coinbase->amount));
      assert(transaction_hash_len >= 32);
      qrl_sha256(transaction_blob, transaction_blob_len, transaction_hash);
      QRL_LOG("transaction_hash coinbase: \n");
      qrl_dump(transaction_hash, 32);
      free(transaction_blob);
      break;
    }
    case QRL__TRANSACTION__TRANSACTION_TYPE_LATTICE_PK:
    case QRL__TRANSACTION__TRANSACTION_TYPE_MESSAGE:
    case QRL__TRANSACTION__TRANSACTION_TYPE_TOKEN:
    case QRL__TRANSACTION__TRANSACTION_TYPE_TRANSFER_TOKEN:
    case QRL__TRANSACTION__TRANSACTION_TYPE_SLAVE:
    case QRL__TRANSACTION__TRANSACTION_TYPE_MULTI_SIG_CREATE:
    case QRL__TRANSACTION__TRANSACTION_TYPE_MULTI_SIG_SPEND:
    case QRL__TRANSACTION__TRANSACTION_TYPE_MULTI_SIG_VOTE:
    case QRL__TRANSACTION__TRANSACTION_TYPE_PROPOSAL_CREATE:
    case QRL__TRANSACTION__TRANSACTION_TYPE_PROPOSAL_VOTE:

    default:
      assert(0);
  }

  return;
}

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
  qrl_log_level = ~0 & ~QRL_LOG_TRACE; /*
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

  qrl_init_grpc();
#define QRL_NODE_ADDRESS "mainnet-1.automated.theqrl.org:19009"
  char *dest = "http://" QRL_NODE_ADDRESS "/qrl.PublicAPI/GetHeight";
  ProtobufCBinaryData payload = {5, (uint8_t[]){0, 0, 0, 0, 0}};
  // sleep(5);
  int *volatile is_finish1 = &(int){0};
  qrl_add_grpc_transfer(dest, payload, NULL, is_finish1);
  int *volatile is_finish2 = &(int){0};
  qrl_add_grpc_transfer(dest, payload, NULL, is_finish2);
  int *volatile is_finish3 = &(int){0};
  qrl_add_grpc_transfer(dest, payload, NULL, is_finish3);
  int *volatile is_finish4 = &(int){0};
  qrl_add_grpc_transfer(dest, payload, NULL, is_finish4);
  int *volatile is_finish5 = &(int){0};
  qrl_add_grpc_transfer(dest, payload, NULL, is_finish5);
  int *volatile is_finish6 = &(int){0};
  qrl_add_grpc_transfer(dest, payload, NULL, is_finish6);
  int *volatile is_finish7 = &(int){0};
  qrl_add_grpc_transfer(dest, payload, NULL, is_finish7);
  int *volatile is_finish8 = &(int){0};
  qrl_add_grpc_transfer(dest, payload, NULL, is_finish8);
  int *volatile is_finish9 = &(int){0};
  qrl_add_grpc_transfer(dest, payload, NULL, is_finish9);
  int *volatile is_finish10 = &(int){0};
  qrl_add_grpc_transfer(dest, payload, NULL, is_finish10);
  while (!(*is_finish1 && *is_finish2 && *is_finish3 && *is_finish4 &&
           *is_finish5 && *is_finish6 && *is_finish7 && *is_finish8 &&
           *is_finish9 && *is_finish10)) {
  }
  qrl_shutdown_grpc();
  //    while (1) {
  //    Qrl__GetHeightReq req = QRL__GET_HEIGHT_REQ__INIT;
  //    Qrl__GetHeightResp *resp = qrl_get_height(req);
  //    QRL_LOG("current height %d\n", resp->height);
  //    current_height = resp->height;
  //    qrl__get_height_resp__free_unpacked(resp, NULL);
  //    sleep(5);
  //    }
  // qrl_gen_keypair(0x020500);

  return 0;
}
