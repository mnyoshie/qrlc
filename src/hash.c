#include "hash.h"
#include "utils.h"
#include "cryptonight/hash-ops.h"

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
void qrl_sha256(qu8 *digest, const void *msg, size_t msg_len) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  assert(mdctx != NULL);
  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
    assert(0);
  }

  if (EVP_DigestUpdate(mdctx, msg, msg_len) != 1) {
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

/*------------------\
 *  HFUNC RANDOMX   |
 `-----------------*/
/* randomx header hashing function */
qvec_t hfunc_randomx(const hfunc_ctx *ctx, const qvec_t msg) {
  assert(ctx->digest_len >= RANDOMX_HASH_SIZE);

  qu8 *digest = malloc(ctx->digest_len);
  assert(digest != NULL);

  randomx_calculate_hash(ctx->randomx.machine, msg.data, msg.len, digest);

  return (qvec_t){.data=digest, .len=ctx->digest_len};
}

/*----------------------\
 *  HFUNC CRYPTONIGHT   |
 `---------------------*/
/* cryptonight1 header hashing function */
qvec_t hfunc_cryptonight1(const hfunc_ctx *ctx, const qvec_t msg) {
  /* HASH_SIZE defined in cryptonight/hash-ops.h */
  assert(ctx->digest_len >= HASH_SIZE);
  qu8 *digest = malloc(ctx->digest_len);
  assert(digest != NULL);
  cn_slow_hash(msg.data, msg.len, (void*)digest, 1 /* variant */, 0 /* pre-hashed*/, 0 /* height */);

  return (qvec_t){.data=digest, .len=ctx->digest_len};
}
