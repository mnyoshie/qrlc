#ifndef QHASH_H
#define QHASH_H

#include <assert.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "include/types.h"
#include "randomx/randomx.h"
#include "cryptonight/hash-ops.h"

typedef struct hfunc_ctx hfunc_ctx;
typedef qvec_t (*hfunc_func)(hfunc_ctx , qvec_t msg);
struct hfunc_ctx {
  size_t digest_len;
  union {
    void *userdata;
    struct {
      randomx_cache *cache;
      randomx_vm *machine;
    } randomx;
    struct {
      randomx_cache *cache;
      randomx_vm *machine;
    } cryptonight;
  };
  hfunc_func hfunc;
//void (*hfunc)(struct hash_func *, qvec_t digest, qvec_t msg);
};

/*------------\
 * SHAKE-128  |
 *-----------*/
extern void qrl_shake128(qvec_t digest, qvec_t msg);

/*------------\
 * SHAKE-256  |
 *-----------*/
extern void qrl_shake256(qvec_t digest, qvec_t message);

/*------------\
 *  SHA-256   |
 *-----------*/
extern void qrl_sha256(qu8 *digest, const void *msg, size_t msg_len);

/*------------\
 *  RANDOMX   |
 *-----------*/
extern void qrl_randomx_hash(qvec_t digest, qvec_t message, qvec_t seed);
extern void qrl_randomx_hash2(randomx_vm *machine, qvec_t digest, qvec_t message);

extern qvec_t hfunc_randomx(hfunc_ctx ctx, qvec_t msg);
extern qvec_t hfunc_cryptonight1(hfunc_ctx ctx, qvec_t msg);
#endif /* QHASH_H */
