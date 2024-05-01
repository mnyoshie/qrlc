#include "randomx/randomx.h"
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"
#include "hash.h"
#include "chain.h"
#include "rx-slow-hash.h"

#include "include/types.h"

#include "dev_config.h"
//#include "include/qrl.pb-c.h"

#ifdef NDEBUG
#  error "Don't turn NDEBUG!"
#endif

#include <assert.h>

static const char *qrl_license = 
#include "license.c"

const char *qrl_get_license(void) {
  return qrl_license;
}

extern int qrl_gen_keypair(int);
extern int qrl_verify_sig(qvec_t pkey, qvec_t msg, qvec_t sig);
extern qvec_t qrl_compute_hash_hdr(const qblock_hdr_t block_header, hfunc_ctx hfunc);

/* clang-format off */
/* computes hash header and writes 32 bytes to hash_header */
//void qrl_compute_hash_header(const qblock_hdr_t block_header,
//                             qvec_t hash_header, struct hash_func *hash_func) {
//  assert(hash_header.data != NULL);
//  //assert(seed_hash.len == 32);
//  struct inctr_t ctr = {0};
//  size_t sincr = 8;
//
//  /* PHASE 1 */
//  /* unsafe memory magic */
//  uint8_t blob1[8 + 8 + 32 + 8 + 8 + 32] = {0};
//
//  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_header.block_number)}, sincr);
//  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_header.timestamp)}, sincr);
//  sincr = 32;
//  memcpy(blob1 + incrementp(&ctr, sincr), block_header.hash_phdr.data, sincr);
//  sincr = 8;
//  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_header.reward_block)}, sincr);
//  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_header.reward_fee)}, sincr);
//  sincr = 32;
//  memcpy(blob1 + incrementp(&ctr, sincr), block_header.merkle_root.data, sincr);
//
//  uint8_t blob1_md[58] = {0};
//  qrl_shake128((qvec_t){.len=58, .data=blob1_md}, (qvec_t){.len=ctr.i, .data=blob1});
//
//  /* PHASE 2 */
//  uint8_t blob2[1 + 58] = {0};
//  memcpy(blob2 + 1, blob1_md, 58);
//
//  uint8_t mining_nonce_bytes[17] = {0};
//  memcpy(mining_nonce_bytes, &(uint32_t){QINT2BIG_32(block_header.mining_nonce)}, 4);
//  memcpy(mining_nonce_bytes + 4, &(uint64_t){QINT2BIG_64(block_header.extra_nonce)}, 8);
//
//  /* mining nonce offset = 39 */
//  /* 76 -18  = 58*/
//  const int mining_nonce_offset = QRL_BLOCK_MINING_NONCE_OFFSET;
//
//  /* JUST...... WHY? */
//  /* mining_blob_final = mining_blob_final[:nonce_offset] + mining_nonce_bytes +
//   * mining_blob_final[nonce_offset:] */
//  uint8_t mining_blob_final[76] = {0};
//  memcpy(mining_blob_final, blob2, mining_nonce_offset);
//  memcpy(mining_blob_final + mining_nonce_offset, mining_nonce_bytes, 17);
//  memcpy(mining_blob_final + mining_nonce_offset + 17,
//         blob2 + mining_nonce_offset, 59 - mining_nonce_offset);
//
//  /* XXX: hfunc changes depending on the seed height */
//  hash_func->hfunc(hash_func, (qvec_t){.data=mining_blob_final, .len=76});
//}

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
          32 +
          transaction.signature.len +
          transaction.public_key.len;
      uint8_t *transaction_blob = malloc(transaction_blob_len);
      assert(transaction_blob != NULL);

      sincr = 32;
      memcpy(transaction_blob + incrementp(&ctr, sincr), data_hash, sincr);

      sincr = transaction.signature.len;
      memcpy(transaction_blob + incrementp(&ctr, sincr), transaction.signature.data, sincr);

      sincr = transaction.public_key.len;
      memcpy(transaction_blob + incrementp(&ctr, sincr), transaction.public_key.data, sincr);

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
  struct inctr_t ctr = {0};
      size_t transaction_blob_len =
          transaction.master_addr.len +
          transaction.coinbase.addr_to.len +
          sizeof(transaction.nonce) +
          sizeof(transaction.coinbase.amount);

      char *transaction_blob = malloc(transaction_blob_len);
      assert(transaction_blob != NULL);

      sincr = transaction.master_addr.len;
      memcpy(transaction_blob + incrementp(&ctr, sincr), transaction.master_addr.data, sincr);

      sincr = transaction.coinbase.addr_to.len;
      memcpy(transaction_blob + incrementp(&ctr, sincr), transaction.coinbase.addr_to.data, sincr);

      sincr = sizeof(transaction.nonce);
      memcpy(transaction_blob + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(transaction.nonce)}, sincr);

      sincr = sizeof(transaction.coinbase.amount);
      memcpy(transaction_blob + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(transaction.coinbase.amount)}, sincr);

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

  qchain_t *chain = qrl_open_chain("/storage/6366-6331/Android/data/com.termux/files/qrl/state");
  printf("chain height %" PRIu64"\n", qrl_get_chain_height(chain));

  qu64 seedheight = rx_seedheight(1);
  qblock_t *seed_block = qrl_get_block_by_number(chain, seedheight);

  randomx_flags flags = randomx_get_flags();
  randomx_cache *cache = randomx_alloc_cache(flags);
  randomx_init_cache(cache, seed_block->block_hdr.hash_hdr.data, seed_block->block_hdr.hash_hdr.len);
  randomx_vm *machine = randomx_create_vm(flags, cache, NULL);

  hfunc_ctx hash_func;
  hash_func.digest_len = 32;
  hash_func.randomx.machine = machine;
  hash_func.randomx.cache = cache;
  hash_func.hfunc = hfunc_randomx;
  free_qblock(seed_block);

  for (qu64 i = 2048; i < 6600; i++) {
    qblock_t *qblock = qrl_get_block_by_number(chain, i);

    qu8 hashheader[59] = {0};

    if (rx_seedheight(i) != seedheight) {
      printf("seed height change from %d to %d at height %d\n", seedheight, rx_seedheight(i), i);
      randomx_destroy_vm(machine);
      randomx_release_cache(cache);

      cache = randomx_alloc_cache(flags);
      seedheight = rx_seedheight(i);
      seed_block = qrl_get_block_by_number(chain, seedheight);

      randomx_init_cache(cache, seed_block->block_hdr.hash_hdr.data, seed_block->block_hdr.hash_hdr.len);

      machine = randomx_create_vm(flags, cache, NULL);
      hash_func.randomx.machine = machine;
      hash_func.randomx.cache = cache;

      free_qblock(seed_block);
    }
    qvec_t hash_hdr = qrl_compute_hash_hdr(qblock->block_hdr, hash_func);
    if (memcmp(hash_hdr.data, qblock->block_hdr.hash_hdr.data, 32)) {
      assert(0);
    }
    free(hash_hdr.data);
    print_qblock(qblock);
    //printf("h: %lu\n", i);
//    printf("real: \n");
//    qrl_dump(hashheader, 32);
//    printf("computed: \n");
//    qrl_dump(qblock1->block_hdr.header_hash.data, 32);
    free_qblock(qblock);
  }

  randomx_destroy_vm(machine);
  randomx_release_cache(cache);
  qrl_close_chain(chain);


  return 0;
}
