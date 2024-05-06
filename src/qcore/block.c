#include "hash.h"
#include "utils.h"
#include "block.h"
#include "tx.h"
#include "dev_config.h"

qvec_t qrl_compute_hash_hdr(const qblock_hdr_t *block_hdr, const hfunc_ctx *hfunc) {
  /* 0 + SHAKE128(block_number || timestamp || hash_phdr || reward_block || reward_fee, 58) */
  struct inctr_t ctr = {0};
  size_t sincr = 0;

  /* PHASE 1 */
  /* unsafe memory magic */
  uint8_t blob1[8 + 8 + 32 + 8 + 8 + 32] = {0};

  sincr = 8;
  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_hdr->block_number)}, sincr);
  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_hdr->timestamp)}, sincr);

  sincr = 32;
  memcpy(blob1 + incrementp(&ctr, sincr), block_hdr->hash_phdr.data, sincr);

  sincr = 8;
  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_hdr->reward_block)}, sincr);
  memcpy(blob1 + incrementp(&ctr, sincr), &(uint64_t){QINT2BIG_64(block_hdr->reward_fee)}, sincr);

  sincr = 32;
  memcpy(blob1 + incrementp(&ctr, sincr), block_hdr->merkle_root.data, sincr);

//  uint8_t blob1_md[58] = {0};

  /* PHASE 2 */
  uint8_t blob2[1 + 58] = {0};
  qrl_shake128((qvec_t){.len=58, .data=blob2 + 1}, (qvec_t){.len=ctr.i, .data=blob1});
  //memcpy(blob2 + 1, blob1_md, 58);

  uint8_t mining_nonce_bytes[17] = {0};
  memcpy(mining_nonce_bytes, &(uint32_t){QINT2BIG_32(block_hdr->mining_nonce)}, 4);
  memcpy(mining_nonce_bytes + 4, &(uint64_t){QINT2BIG_64(block_hdr->extra_nonce)}, 8);

  /* mining nonce offset = 39 */
  /* 76 -18  = 58*/
  const int mining_nonce_offset = QRL_BLOCK_MINING_NONCE_OFFSET;

  /* mining_blob_final = mining_blob_final[:nonce_offset] + mining_nonce_bytes +
   * mining_blob_final[nonce_offset:] */
  uint8_t mining_blob_final[76] = {0};
  ctr.i = 0;

  sincr = mining_nonce_offset;
  memcpy(mining_blob_final + incrementp(&ctr, sincr), blob2, sincr);

  sincr = 17;
  memcpy(mining_blob_final + incrementp(&ctr, sincr), mining_nonce_bytes, sincr);

  sincr = 59 - mining_nonce_offset;
  memcpy(mining_blob_final + incrementp(&ctr, sincr), blob2 + mining_nonce_offset, sincr);

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
  return hfunc->hfunc(hfunc, (qvec_t){.data=mining_blob_final, .len=ctr.i});
}

int qrl_verify_qblock(const qblock_t *qblock, const hfunc_ctx *hfunc) {
  int ret = 1, has_invalid = 0;
  qvec_t hash_hdr = qrl_compute_hash_hdr(&qblock->block_hdr, hfunc);
  assert(hash_hdr.data != NULL);

  if (memcmp(hash_hdr.data, qblock->block_hdr.hash_hdr.data, 32)) {
      QRL_LOG_EX(QRL_LOG_ERROR, "header hash mismatched\n");
    goto exit;
  }

  if (qblock->nb_txs == 0)
    goto exit;
  if (qblock->txs[0].tx_type != QTX_COINBASE)
    goto exit;

  if (qrl_verify_qtx(&qblock->txs[0]))
    goto exit;

  for (size_t i = 1; i < qblock->nb_txs; i++) {
    if (qblock->txs[i].tx_type == QTX_COINBASE) {
      QRL_LOG_EX(QRL_LOG_ERROR, "multiple coinbase transaction\n");
      goto exit;
    }
    if (qrl_verify_qtx(&qblock->txs[i])) {
      QRL_LOG_EX(QRL_LOG_ERROR, "invalid tx\n");
      has_invalid = 1;
      continue;
    }
  }

exit:
  free(hash_hdr.data);
  return has_invalid ? 1 : 0;
}
