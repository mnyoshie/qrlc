#include "hash.h"
#include "utils.h"
#include "block.h"
#include "tx.h"
#include "dev_config.h"

qvec_t qrl_generate_mining_blob(const qblock_hdr_t *block_hdr) {
  struct inctr_t ctr = {0};
  size_t sincr = 0;

  /* PHASE 1 */
  size_t blob1_len =
    sizeof(block_hdr->block_number) +
    sizeof(block_hdr->timestamp) +
    block_hdr->hash_phdr.len +
    sizeof(block_hdr->reward_block) +
    sizeof(block_hdr->reward_fee) +
    block_hdr->merkle_root.len;

  qu8 *blob1 = malloc(blob1_len);
  assert(blob1 != NULL);

  sincr = sizeof(block_hdr->block_number);
  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_hdr->block_number)}, sincr);
  sincr = sizeof(block_hdr->timestamp);
  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_hdr->timestamp)}, sincr);

  sincr = block_hdr->hash_phdr.len;
  memcpy(blob1 + incrementp(&ctr, sincr), block_hdr->hash_phdr.data, sincr);

  sincr = sizeof(block_hdr->reward_block);
  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_hdr->reward_block)}, sincr);
  sincr = sizeof(block_hdr->reward_fee);
  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_hdr->reward_fee)}, sincr);

  sincr = block_hdr->merkle_root.len;
  memcpy(blob1 + incrementp(&ctr, sincr), block_hdr->merkle_root.data, sincr);

//  uint8_t blob1_md[58] = {0};

  /* PHASE 2 */
  uint8_t blob2[1 + 58] = {0};
  qrl_shake128((qvec_t){.len=58, .data=blob2 + 1}, (qvec_t){.len=ctr.i, .data=blob1});
  free(blob1);
  //memcpy(blob2 + 1, blob1_md, 58);

  uint8_t mining_nonce_bytes[17] = {0};
  memcpy(mining_nonce_bytes, &(uint32_t){QINT2BIG_32(block_hdr->mining_nonce)}, 4);
  memcpy(mining_nonce_bytes + 4, &(uint64_t){QINT2BIG_64(block_hdr->extra_nonce)}, 8);

  /* mining nonce offset = 39 */
  /* QMINING_BLOB_SIZE -18  = 58*/
  const int mining_nonce_offset = QBLOCK_MINING_NONCE_OFFSET;

  /* mining_blob_final = mining_blob_final[:nonce_offset] + mining_nonce_bytes +
   * mining_blob_final[nonce_offset:] */
  qvec_t mining_blob_final = qrl_qvecmalloc(QMINING_BLOB_SIZE);
  ctr.i = 0;

  sincr = mining_nonce_offset;
  memcpy(mining_blob_final.data + incrementp(&ctr, sincr), blob2, sincr);

  sincr = 17;
  memcpy(mining_blob_final.data + incrementp(&ctr, sincr), mining_nonce_bytes, sincr);

  sincr = 59 - mining_nonce_offset;
  memcpy(mining_blob_final.data + incrementp(&ctr, sincr), blob2 + mining_nonce_offset, sincr);
  return mining_blob_final;

}

static inline qvec_t compute_merkle_hash_iterative(qvec_t *vec, size_t nb_vec) {
  if (nb_vec == 0) {
    QRL_LOG_EX(QRL_LOG_WARNING, "nb_vec == 0\n");
    return QVEC_NULL;
  }
  if (nb_vec == 1)
    return qrl_qveccpy(*vec);

  qvec_t *hashed = NULL;
  size_t nb_hashed = nb_vec / 2;

  if (nb_vec % 2) nb_hashed += 1;
  hashed = malloc(sizeof(*hashed) * nb_hashed);
  const size_t original_nb_hashed = nb_hashed;

  for (size_t i = 0; i < original_nb_hashed; i++) {
    hashed[i] = qrl_qvecmalloc(32);
  }

  while (nb_vec > 1) {
    nb_hashed = nb_vec / 2;
    if (nb_vec % 2) nb_hashed += 1;

    /* concatenate and hash */
    for (size_t i = 0; i < nb_vec / 2; i++) {
      qvec_t catted = qrl_qveccat(vec[i*2], vec[i*2 + 1]);
      qrl_sha256(hashed[i].data, catted.data, catted.len);
      free(catted.data);
    }

    if (nb_vec % 2) {
      free(hashed[nb_hashed - 1].data);
      /* we can't just `memcpy(hashed[nb_hashed - 1].data, vec[nb_vec - 1].data, vec[nb_vec - 1].len)`
       * since hashed[].data only have 32 bytes allocated from qrl_qvecmalloc(32).
       */
      hashed[nb_hashed - 1] = qrl_qveccpy(vec[nb_vec - 1]);
    }
    vec = hashed;
    nb_vec = nb_hashed;
  } 

  qvec_t ret = *hashed;
  for (size_t i = 1; i < original_nb_hashed; i++) {
    qrl_qvecfree(hashed[i]);
  }
  free(hashed);

  return ret;
}

qvec_t qrl_compute_merkle_root(qtx_t *txs, size_t nb_txs) {
  qvec_t merkle_root = QVEC_NULL;

  if (nb_txs == 0) {
    QRL_LOG_EX(QRL_LOG_WARNING, "nb_txs == 0\n");
    return QVEC_NULL;
  }

  qvec_t *txvec = malloc(sizeof(*txvec)*nb_txs);
  for (size_t i = 0; i < nb_txs; i++) {
    txvec[i] = txs[i].tx_hash;
  }

  merkle_root = compute_merkle_hash_iterative(txvec, nb_txs);
  free(txvec);

  return merkle_root;
}

qvec_t qrl_compute_hash_hdr(const qblock_hdr_t *block_hdr, const hfunc_ctx *hfunc) {
  /* 0 + SHAKE128(block_number || timestamp || hash_phdr || reward_block || reward_fee, 58) */
  qvec_t blob = qrl_generate_mining_blob(block_hdr);
  assert(blob.len == QMINING_BLOB_SIZE);
  qu8 mining_blob[QMINING_BLOB_SIZE];
  /* copy on stack */
  memcpy(mining_blob, blob.data, QMINING_BLOB_SIZE);
  qrl_qvecfree(blob);

  /* Back in the days of cryptonight, it was as simple to call the cryptonight hash
   * function as:
   *
   *     digest = cryptonight(message);
   *
   * but since the randomx fork, it need to take an extra randomx_vm * parameter, which is
   * initialized from a hash_header of a block from a certain height (called seed block):
   *
   *   randomx_cache = init_cache(hash_header)
   *   randomx_machine = init_machine(cache)
   *   digest = randomx(randomx_machine, message)
   *
   * This initialization of cache is expensive at every hash calculation at every
   * call of compute_hash_hdr.
   *
   * Knowing that the cache only needs to be reinitialize about 2048*n+65 blocks or so,
   * we can considerably reduce it by initializing the cache outside of this
   * function stored in hfunc->randomx.*
   *
   * This architecture makes sure that compute_hash_hdr is independent of seed_block,
   * prevents outside call of get_block_by_number, prevents reinitialization of cache
   * at every same seed_height and hopes to solve future algo forks
   *
   * */
  /* XXX: hfunc->randomx.{machine,cache} are initialized outside of this function and
   * changes depending on the seed height */
  return hfunc->hfunc(hfunc, (qvec_t){.data=mining_blob, .len=QMINING_BLOB_SIZE});
}

/* Verifies block headsr and transactions */ 
int qrl_verify_qblock(const qblock_t *qblock, const hfunc_ctx *hfunc) {
  int ret = 0xff;
  qvec_t hash_hdr = QVEC_NULL, merkle_root = QVEC_NULL;

  hash_hdr = qrl_compute_hash_hdr(&qblock->block_hdr, hfunc);
  assert(hash_hdr.data != NULL);
#define EXITIF(x, ...)                                \
  do {                                                \
    if (x) {                                          \
      QRL_LOG_EX(QRL_LOG_ERROR, #x ": " __VA_ARGS__); \
      goto exit;                                      \
    }                                                 \
  } while (0)

  EXITIF(memcmp(hash_hdr.data, qblock->block_hdr.hash_hdr.data, 32), "hash header mismatch\n");
  EXITIF(qblock->nb_txs == 0, "no transaction\n");
  EXITIF(qblock->txs[0].tx_type != QTX_COINBASE, "transaction does not start with coinbase\n");
  EXITIF(qblock->txs[0].nonce != qblock->block_hdr.block_number + 1, "invalid coinbase nonce\n");
  EXITIF(qrl_verify_qtx(&qblock->txs[0]), "block verification failed\n");
  for (size_t i = 1; i < qblock->nb_txs; i++) {
    EXITIF (qblock->txs[i].tx_type == QTX_COINBASE, "multiple coinbase transaction\n");
  }
  for (size_t i = 1; i < qblock->nb_txs; i++) {
    EXITIF(qrl_verify_qtx(&qblock->txs[i]), "invalid tx at index %zu\n", i);
  }
  merkle_root = qrl_compute_merkle_root(qblock->txs, qblock->nb_txs);
  EXITIF(memcmp(merkle_root.data, qblock->block_hdr.merkle_root.data, 32), "merkle root mismatch\n");

#undef EXITIF

  ret ^= ret;
exit:
  qrl_qvecfree(hash_hdr);
  qrl_qvecfree(merkle_root);
  return ret;
}
