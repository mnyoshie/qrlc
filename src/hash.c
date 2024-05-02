#include "hash.h"

extern
void cn_slow_hash(const void *data, size_t length, char *hash, int variant, int prehashed);

/*------------\
 * SHAKE-128  |
 *-----------*/
void qrl_shake128(qvec_t digest, qvec_t msg) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  assert(mdctx != NULL);
  if (EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  if (EVP_DigestUpdate(mdctx, msg.data, msg.len) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  if (EVP_DigestFinalXOF(mdctx, digest.data, digest.len) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  EVP_MD_CTX_free(mdctx);
}

/*------------\
 * SHAKE-256  |
 *-----------*/
// void qrl_shake256(uint8_t *message, int message_len, uint8_t *digest,
//                   int digest_len) {
void qrl_shake256(qvec_t digest, qvec_t msg) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  assert(mdctx != NULL);
  if (EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL) != 1) {
    assert(0);
  }

  if (EVP_DigestUpdate(mdctx, msg.data, msg.len) != 1) {
    assert(0);
  }

  if (EVP_DigestFinalXOF(mdctx, digest.data, digest.len) != 1) {
    assert(0);
  }

  EVP_MD_CTX_free(mdctx);
}

/*------------\
 *  SHA-256   |
 *-----------*/
void qrl_sha256(const void *message, int message_len, uint8_t *digest) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  assert(mdctx != NULL);
  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
    assert(0);
  }

  if (EVP_DigestUpdate(mdctx, message, message_len) != 1) {
    assert(0);
  }

  unsigned int len;
  if (EVP_DigestFinal_ex(mdctx, digest, &len) != 1) {
    assert(0);
  }
  /* paranoid */
  assert(len == 32);

  EVP_MD_CTX_free(mdctx);
}

/*------------\
 *  RANDOMX   |
 *-----------*/
void qrl_randomx_hash(qvec_t digest, qvec_t msg, qvec_t seed) {
    randomx_flags flags = randomx_get_flags();
    randomx_cache *cache = randomx_alloc_cache(flags);
    randomx_init_cache(cache, seed.data, seed.len);
    randomx_vm *machine = randomx_create_vm(flags, cache, NULL);

    assert(digest.len >= RANDOMX_HASH_SIZE);

    randomx_calculate_hash(machine, msg.data, msg.len, digest.data);

    randomx_destroy_vm(machine);
    randomx_release_cache(cache);
}

void qrl_randomx_hash2(randomx_vm *machine, qvec_t digest, qvec_t msg) {
  assert(digest.len >= RANDOMX_HASH_SIZE);

  randomx_calculate_hash(machine, msg.data, msg.len, digest.data);
}

qvec_t hfunc_randomx(hfunc_ctx ctx, qvec_t msg) {
  qu8 *digest = malloc(ctx.digest_len);
  assert(digest != NULL);

  char buf[RANDOMX_HASH_SIZE] = {0};
  randomx_calculate_hash(ctx.randomx.machine, msg.data, msg.len, buf);

  memcpy(digest, buf, ctx.digest_len);
  return (qvec_t){.data=digest, .len=ctx.digest_len};
}

qvec_t hfunc_cryptonight7(hfunc_ctx *ctx, qvec_t msg) {
  qu8 *digest = malloc(ctx->digest_len);
  assert(digest != NULL);
  cn_slow_hash(msg.data, msg.len, (void*)digest, 7, 0);

  return (qvec_t){.data=digest, .len=ctx->digest_len};
}
