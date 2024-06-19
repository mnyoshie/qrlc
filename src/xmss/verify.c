/* xmss.c - Experimental QRL XMSS
 *
 * Copyright (c) 2017, 2018 The QRL Contributors
 * Copyright (c) 2024 The QRLC Authors
 *
 * Released under MIT License
 *
 * NOTE:
 *
 * Most of this code was borrowed from qrllib/xmss-alt and has been refractored.
 *
 * The original implementation was written by
 *   Andreas Hülsing
 *   Joost Rijneveld
 * */

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "verify.h"

/* verification doesn't need extra overhead to secure heap
 */
#define OPENSSL_secure_malloc(x) malloc(x)
#define OPENSSL_secure_free(x) free(x)

#ifdef __unix__
#  include <sys/types.h>
#else
/* https://stackoverflow.com/a/34580624/11484097 */
#  if SIZE_MAX == UINT_MAX
typedef int ssize_t; /* common 32 bit case */
#    define SSIZE_MIN INT_MIN
#    define SSIZE_MAX INT_MAX
#  elif SIZE_MAX == ULONG_MAX
typedef long ssize_t; /* linux 64 bits */
#    define SSIZE_MIN LONG_MIN
#    define SSIZE_MAX LONG_MAX
#  elif SIZE_MAX == ULLONG_MAX
typedef long long ssize_t; /* windows 64 bits */
#    define SSIZE_MIN LLONG_MIN
#    define SSIZE_MAX LLONG_MAX
#  elif SIZE_MAX == USHRT_MAX
typedef short ssize_t; /* is this even possible? */
#    define SSIZE_MIN SHRT_MIN
#    define SSIZE_MAX SHRT_MAX
#  elif SIZE_MAX == UINTMAX_MAX
typedef intmax_t ssize_t; /* last resort, chux suggestion */
#    define SSIZE_MIN INTMAX_MIN
#    define SSIZE_MAX INTMAX_MAX
#  else
#    error platform has exotic SIZE_MAX
#  endif /* SSIZE */
#endif   /* include "sys/types.h"*/

#include <openssl/evp.h>
#include <openssl/sha.h>


#if !defined(QDEBUG)
#  define LOG(...) \
    do {           \
      ;            \
    } while (0)
#else
#  define LOG(...)                                                        \
    do {                                                                  \
      fprintf(stderr, "%s:%d @ %s(...): ", __FILE__, __LINE__, __func__); \
      fprintf(stderr, __VA_ARGS__);                                       \
    } while (0)

#endif

#define RETURNIF(cond, ret, ...) \
  do {                           \
    if (cond) {                  \
      LOG(#cond ": " __VA_ARGS__);  \
      return ret;                \
    }                            \
  } while (0)


#define VEC_NULL \
  (vec_t) { .data = NULL, .len = 0 }

typedef struct tree_t tree_t;
struct tree_t {
  vec_t hash;

  /* node height is the rows,
   * node ndx is the columns of the tree */
  ssize_t node_height;
  size_t node_ndx;
  tree_t *left, *right;
};


typedef struct hfunc_ctx hfunc_ctx;
struct hfunc_ctx {
  size_t digest_len;
  vec_t (*hfunc)(hfunc_ctx *ctx, struct vec_t msg);
};

typedef struct {
  uint32_t len_1;
  uint32_t len_2;
  uint32_t len;
  uint32_t n;
  uint32_t w;
  uint32_t log_w;
  uint32_t keysize;

  /* misc params */
  hfunc_ctx hfunc;
} wots_params;

struct xmss_tree_t {
  tree_t *tree;
/*------------------------------------------------.
|  4 bits |  4 bits  | 4 bits |  4 bits  | 8 bits |
|    SIG  |     HF   |   AF   |    P1    |   P2   |
`------------------------------------------------*/
  uint8_t sig, hf, af, p1, p2; 
  wots_params *wparams;
  vec_t sk_seed;
  vec_t sk_prf;
  vec_t pub_seed;
};

static wots_params wots_init(hfunc_ctx hfunc, int n, int w) {
  wots_params params;
  params.n = n;
  params.w = w;
  params.log_w = (int)log2(w);
  params.len_1 = (int)ceil(((8 * n) / params.log_w));
  params.len_2 = (int)floor(log2(params.len_1 * (w - 1)) / params.log_w) + 1;
  params.len = params.len_1 + params.len_2;
  params.keysize = params.len * params.n;

  params.hfunc = hfunc;
  return params;
}

/*----------- BEGIN PRELIMINARIES ----------*/

/* ARCHITECTURE ---- This implementation is not the most efficient and that's
 * ok. it's goal is to convey an idea in the clearest way possible.
 */

/* vec memory utilities */
static vec_t vecmalloc(size_t len);
static void vecfree(vec_t v);

/* copies v */
static vec_t veccpy(vec_t v);

/* creates vec from data and len */
static vec_t vecmem(void *data, size_t len);

/* concatenates a and b */
static vec_t veccat(vec_t a, vec_t b);

/* xor's a and b (a.len must equal b.len) */
static vec_t vecxor(vec_t a, vec_t b);

/* compute sha256 sum of msg and returns it */
static vec_t vechash_sha256(vec_t msg);
static vec_t hfunc_sha256(hfunc_ctx *hfunc, vec_t msg);

/* shake extendable output functions produces digest of
 * len, `digest_len`
 */
static vec_t vechash_shake128(vec_t msg, size_t digest_len);
static vec_t vechash_shake256(vec_t msg, size_t digest_len);

static vec_t hfunc_shake128(hfunc_ctx *hfunc, vec_t msg);
static vec_t hfunc_shake256(hfunc_ctx *hfunc, vec_t msg);

/* ---------- END PRELIMINARIES -----------
 *    --- Thats basically all the functions */

/* unused functions */
#if 0 
static inline void setLayerADRS(uint32_t adrs[8], uint32_t layer) { adrs[0] = layer; }

static inline void setTreeADRS(uint32_t adrs[8], uint64_t tree) {
  adrs[1] = (uint32_t)(tree >> 32);
  adrs[2] = (uint32_t)tree;
}
#endif

static inline void setType(uint32_t adrs[8], uint32_t type) {
  adrs[3] = (type);
  for (int i = 4; i < 8; i++) {
    adrs[i] = 0;
  }
}

static inline void setKeyAndMask(uint32_t adrs[8], uint32_t keyAndMask) {
  adrs[7] = (keyAndMask);
}

// OTS

static inline void setOTSADRS(uint32_t adrs[8], uint32_t ots) {
  adrs[4] = (ots);
}

static inline void setChainADRS(uint32_t adrs[8], uint32_t chain) {
  adrs[5] = (chain);
}

static inline void setHashADRS(uint32_t adrs[8], uint32_t hash) {
  adrs[6] = (hash);
}

// L-tree

static inline void setLtreeADRS(uint32_t adrs[8], uint32_t ltree) {
  adrs[4] = (ltree);
}

// Hash Tree & L-tree

static inline void setTreeHeight(uint32_t adrs[8], uint32_t treeHeight) {
  adrs[5] = (treeHeight);
}

static inline void setTreeIndex(uint32_t adrs[8], uint32_t treeIndex) {
  adrs[6] = (treeIndex);
}

static inline void to_byte(uint8_t *out, uint32_t in, uint32_t bytes) {
  for (int32_t i = bytes - 1; i >= 0; i--) {
    out[i] = (uint8_t)(in & 0xff);
    in = in >> 8;
  }
}

static inline uint8_t *addr_to_byte(uint8_t *bytes, const uint32_t addr[8]) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  for (int i = 0; i < 8; i++) to_byte(bytes + i * 4, addr[i], 4);
  return bytes;
#else
  memcpy(bytes, addr, 32);
  return bytes;
#endif
}

static inline vec_t core_hash(hfunc_ctx *hfunc, const uint32_t type, vec_t key,
                              vec_t in, size_t n) {
  //  buf is (toByte(X, 32) || KEY || M)
  char buf[n + key.len + in.len];

  // set toByte
  to_byte((void *)buf, type, n);
  memcpy(buf + n, key.data, key.len);
  memcpy(buf + n + key.len, in.data, in.len);

  return hfunc->hfunc(hfunc, (vec_t){.data = buf, .len = n + key.len + in.len});
}

static inline vec_t prf(hfunc_ctx *hfunc, vec_t in, vec_t key, size_t keylen) {
  return core_hash(hfunc, 3, key, in, keylen);
}

static vec_t h_msg(wots_params *wparams, vec_t in, vec_t key) {
  if (key.len != 3 * wparams->n) {
    LOG("H_msg takes 3n-bit keys, we got n=%u but a keylength of %zu.\n",
        wparams->n, key.len);
    return VEC_NULL;
  }
  return core_hash(&wparams->hfunc, 2, key, in, wparams->n);
}

static inline vec_t hash_h(hfunc_ctx *hfunc, vec_t in, const vec_t pub_seed,
                           unsigned int addr[8], const size_t n) {
  assert(in.len >= 2 * n);

  uint32_t byte_addr[32];

  setKeyAndMask(addr, 0);
  addr_to_byte((uint8_t *)byte_addr, addr);
  vec_t key =
      prf(hfunc, (vec_t){.data = (void *)byte_addr, .len = 32}, pub_seed, n);
  //  Use MSB order
  setKeyAndMask(addr, 1);
  addr_to_byte((uint8_t *)byte_addr, addr);
  vec_t bitmask1 =
      prf(hfunc, (vec_t){.data = (void *)byte_addr, .len = 32}, pub_seed, n);

  setKeyAndMask(addr, 2);
  addr_to_byte((uint8_t *)byte_addr, addr);
  vec_t bitmask2 =
      prf(hfunc, (vec_t){.data = (void *)byte_addr, .len = 32}, pub_seed, n);

  vec_t bitmask = veccat(bitmask1, bitmask2);

  vec_t buf = vecxor(in, bitmask);

  vec_t ret = core_hash(hfunc, 1, key, buf, n);
  vecfree(key);
  vecfree(bitmask1);
  vecfree(bitmask2);
  vecfree(bitmask);
  vecfree(buf);
  return ret;
}

static inline vec_t hash_f(hfunc_ctx *hfunc, vec_t in, vec_t pub_seed,
                           uint32_t addr[8], const size_t n) {
  uint8_t byte_addr[32];

  setKeyAndMask(addr, 0);
  addr_to_byte(byte_addr, addr);
  vec_t key =
      prf(hfunc, (vec_t){.data = (void *)byte_addr, .len = 32}, pub_seed, n);

  setKeyAndMask(addr, 1);
  addr_to_byte(byte_addr, addr);
  vec_t bitmask =
      prf(hfunc, (vec_t){.data = (void *)byte_addr, .len = 32}, pub_seed, n);

  vec_t buf = vecxor(in, bitmask);

  vec_t ret = core_hash(hfunc, 0, key, buf, n);
  vecfree(bitmask);
  vecfree(key);
  vecfree(buf);
  return ret;
}

static vec_t gen_chain(const vec_t in, size_t start, size_t steps,
                       wots_params *wparams, const vec_t pub_seed,
                       uint32_t addr[8]) {
  vec_t out = vecmalloc(wparams->n);
  memcpy(out.data, in.data, wparams->n);

  for (size_t i = start; i < (start + steps) && i < wparams->w; i++) {
    setHashADRS(addr, i);
    vec_t v = hash_f(&wparams->hfunc, out, pub_seed, addr, wparams->n);
    memcpy(out.data, v.data, wparams->n);
    vecfree(v);
  }

  return out;
}

static vec_t ltree_root(wots_params *wparams, vec_t *wots_pk,
                        const vec_t pub_seed, uint32_t addr[8]) {
  unsigned int l = wparams->len;
  unsigned int n = wparams->n;
  uint32_t height = 0;
  uint32_t bound;

  setTreeHeight(addr, height);

  while (l > 1) {
    bound = l >> 1;
    for (uint32_t i = 0; i < bound; i++) {
      setTreeIndex(addr, i);
      vec_t catted = veccat(wots_pk[i * 2], wots_pk[i * 2 + 1]);
      assert(catted.len >= 2 * n);
      vecfree(wots_pk[i]);
      wots_pk[i] = hash_h(&wparams->hfunc, catted, pub_seed, addr, n);
      vecfree(catted);
    }
    if (l & 1) {
      vecfree(wots_pk[l >> 1]);
      wots_pk[l >> 1 /* l/2 */] = veccpy(wots_pk[l - 1]);
      l = (l >> 1) + 1;
    } else {
      l = (l >> 1);
    }
    height++;
    setTreeHeight(addr, height);
  }
  return veccpy(wots_pk[0]);

  // memcpy(leaf, wots_pk, n);
}

inline vec_t vecmem(void *mem, size_t len) {
  char *data = OPENSSL_secure_malloc(len);
  memcpy(data, mem, len);
  return (vec_t){.data = data, .len = len};
}

inline vec_t veccpy(vec_t v) {
  char *data = OPENSSL_secure_malloc(v.len);
  memcpy(data, v.data, v.len);
  return (vec_t){.data = data, .len = v.len};
}

inline void vecfree(vec_t v) { OPENSSL_secure_free(v.data); }

static vec_t vecmalloc(size_t len) {
  char *data = OPENSSL_secure_malloc(len);
  if (data == NULL) {LOG("GOT NULL!\n");}
  return data == NULL ? VEC_NULL : (vec_t){.data = data, .len = len};
}

inline vec_t veccat(vec_t a, vec_t b) {
  size_t len = a.len + b.len;
  char *data = OPENSSL_secure_malloc(len);
  memcpy(data, a.data, a.len);
  memcpy(data + a.len, b.data, b.len);
  return (vec_t){.data = data, .len = len};
}

inline vec_t vecxor(vec_t a, vec_t b) {
  assert(a.len == b.len);
  vec_t ret = vecmalloc(a.len & b.len);

  for (size_t i = 0; i < ret.len; i++) {
    ret.data[i] = a.data[i] ^ b.data[i];
  }

  return ret;
}

////////////
/* vechash_* */

static vec_t vechash_sha256(vec_t msg) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  RETURNIF(mdctx == NULL, VEC_NULL, "panic\n");

  RETURNIF(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1,
    VEC_NULL,
    "panic\n"
  );

  RETURNIF(EVP_DigestUpdate(mdctx, (void *)msg.data, msg.len) != 1,
    VEC_NULL,
    "panic\n"
  );

  vec_t digest = vecmalloc(32);
  unsigned int len;
  if (EVP_DigestFinal_ex(mdctx, (void *)digest.data, &len) != 1) {
    assert(0);
  }
  /* paranoid */
  assert(digest.len == 32);
  digest.len = len;

  //  vecprintx(digest);
  //  puts("");
  EVP_MD_CTX_free(mdctx);
  return digest;
}

static vec_t vechash_shake128(vec_t msg, size_t digest_len) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  RETURNIF(mdctx == NULL, VEC_NULL, "panic\n");
  if (EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  if (EVP_DigestUpdate(mdctx, (void *)msg.data, msg.len) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  vec_t digest = vecmalloc(digest_len);
  if (EVP_DigestFinalXOF(mdctx, (void *)digest.data, digest.len) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  EVP_MD_CTX_free(mdctx);
  return digest;
}

static vec_t vechash_shake256(vec_t msg, size_t digest_len) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  RETURNIF(mdctx == NULL, VEC_NULL, "panic\n");

  if (EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  if (EVP_DigestUpdate(mdctx, (void *)msg.data, msg.len) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  vec_t digest = vecmalloc(digest_len);
  if (EVP_DigestFinalXOF(mdctx, (void *)digest.data, digest.len) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  EVP_MD_CTX_free(mdctx);
  return digest;
}

static vec_t hfunc_sha256(hfunc_ctx *ctx, vec_t msg) {
  assert(ctx->digest_len == 32);
  return vechash_sha256(msg);
}

static vec_t hfunc_shake128(hfunc_ctx *ctx, vec_t msg) {
  return vechash_shake128(msg, ctx->digest_len);
}

static vec_t hfunc_shake256(hfunc_ctx *ctx, vec_t msg) {
  return vechash_shake256(msg, ctx->digest_len);
}

/////////

static wots_params wots_init2(uint8_t hf, int n, int w) {
  switch (hf) {
    case 0:
      return wots_init((hfunc_ctx){.digest_len = n, .hfunc = hfunc_sha256}, n,
                       w);
    case 1:
      return wots_init((hfunc_ctx){.digest_len = n, .hfunc = hfunc_shake128}, n,
                       w);
    case 2:
      return wots_init((hfunc_ctx){.digest_len = n, .hfunc = hfunc_shake256}, n,
                       w);
    default:
      assert(0);
  }
}

static void base_w(int *output, const int out_len, const unsigned char *input,
                   wots_params *params) {
  int in = 0;
  int out = 0;
  uint32_t total = 0;
  int bits = 0;
  int consumed = 0;

  for (consumed = 0; consumed < out_len; consumed++) {
    if (bits == 0) {
      total = input[in];
      in++;
      bits += 8;
    }
    bits -= params->log_w;
    output[out] = (total >> bits) & (params->w - 1);
    out++;
  }
}

/* returns array of wparams->len elements of public keys derived from sig and
 * pub_seed*/
static vec_t *wots_pk_from_sig(vec_t *sig, vec_t msg, wots_params *wparams,
                               vec_t pub_seed, uint32_t addr[8]) {
  uint32_t XMSS_WOTS_LEN = wparams->len;
  uint32_t XMSS_WOTS_LEN1 = wparams->len_1;
  uint32_t XMSS_WOTS_LEN2 = wparams->len_2;
  uint32_t XMSS_WOTS_LOG_W = wparams->log_w;
  uint32_t XMSS_WOTS_W = wparams->w;

  int basew[XMSS_WOTS_LEN];
  int csum = 0;
  unsigned char csum_bytes[((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) + 7) / 8];
  int csum_basew[XMSS_WOTS_LEN2];
  uint32_t i = 0;
  vec_t *pk = OPENSSL_secure_malloc(sizeof(*pk) * XMSS_WOTS_LEN);
  assert(pk != NULL);

  base_w(basew, XMSS_WOTS_LEN1, (void *)msg.data, wparams);

  for (i = 0; i < XMSS_WOTS_LEN1; i++) {
    csum += XMSS_WOTS_W - 1 - basew[i];
  }

  csum = csum << (8 - ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) % 8));

  to_byte(csum_bytes, csum, ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) + 7) / 8);
  base_w(csum_basew, XMSS_WOTS_LEN2, csum_bytes, wparams);

  for (i = 0; i < XMSS_WOTS_LEN2; i++) {
    basew[XMSS_WOTS_LEN1 + i] = csum_basew[i];
  }
  for (i = 0; i < XMSS_WOTS_LEN; i++) {
    setChainADRS(addr, i);
    pk[i] = gen_chain(sig[i], basew[i], XMSS_WOTS_W - 1 - basew[i], wparams,
                      pub_seed, addr);
  }
  return pk;
}

static vec_t *partition(vec_t in, size_t n) {
  assert(in.len % n == 0);
  size_t nb = in.len / n;
  vec_t *ret = OPENSSL_secure_malloc(sizeof(*ret) * nb);
  for (size_t i = 0; i < nb; i++) {
    ret[i] = vecmalloc(n);
    memcpy(ret[i].data, &in.data[i * n], n);
  }
  return ret;
}

static vec_t *get_wsig_from_sig(vec_t sig, size_t s) {
  size_t lbound = 4 + 32;
  /* .len - lbound == wparams->len*32 */
  return partition((vec_t){.data = sig.data + lbound, .len = s}, 32);
}

static vec_t *get_auth_from_sig(vec_t sig, size_t s) {
  size_t lbound = sig.len - s;
  /* lbound == 4 + 32 + wparams->len*32 */
  return partition((vec_t){.data = sig.data + lbound, .len = s}, 32);
}

static vec_t validate_authpath(wots_params *wparams, vec_t leaf,
                               uint32_t leafidx, vec_t *auth, const uint32_t h,
                               vec_t pub_seed, uint32_t addr[8]) {
  size_t auth_ctr = 0;
  size_t n = wparams->n;
  vec_t buf = VEC_NULL;
  if (leafidx & 1) {
    buf = veccat(auth[auth_ctr++], leaf);
  } else
    buf = veccat(leaf, auth[auth_ctr++]);

  for (uint32_t i = 0; i < h - 1; i++) {
    setTreeHeight(addr, i);
    leafidx >>= 1;
    setTreeIndex(addr, leafidx);
    vec_t hashed = hash_h(&wparams->hfunc, buf, pub_seed, addr, n);
    vecfree(buf);
    if (leafidx & 1) {
      vec_t catted = veccat(auth[auth_ctr++], hashed);
      buf = catted;
    } else {
      vec_t catted = veccat(hashed, auth[auth_ctr++]);
      buf = catted;
    }
    // VECDEBUG(buf);
    vecfree(hashed);
  }

  setTreeHeight(addr, (h - 1));
  leafidx >>= 1;
  setTreeIndex(addr, leafidx);
  vec_t ret = hash_h(&wparams->hfunc, buf, pub_seed, addr, n);
  vecfree(buf);
  return ret;
}

#define TOVEC(q) \
  (vec_t) { .data = (void *)q.data, .len = q.len }
#define TOQVEC(v) \
  (vec_t) { .data = (void *)v.data, .len = v.len }

/* for single byte in a uint8_t array */
#define GET_SIGB(x) ((x >> 4) & 0x0f)
#define GET_HFB(x) ((x >> 0) & 0x0f)
#define GET_AFB(x) ((x >> 4) & 0x0f)
#define GET_P1B(x) ((x >> 0) & 0x0f)
/* QRL address descriptor layout DESC (24 bits). */
/*------------------------------------------------.
|  4 bits |  4 bits  | 4 bits |  4 bits  | 8 bits |
|    SIG  |     HF   |   AF   |    P1    |   P2   |
`------------------------------------------------*/
/* 23 bit <-------------------------------- 0 bit */



/* pub_key format (67 octets):
 *
 *    size          |         name            |       description
 * -----------------+-------------------------+----------------------------
 *  3 octets        |      qrl addr desc      |  QRL  address descriptor
 *  ----------------+-------------------------+----------------------------
 *  32 octets       |         root            |       XMSS root
 *  ------------------------------------------+----------------------------
 *  32 octets       |       pub seed          |       public seed
 *
 *
 *
 * sig format:
 *
 *    size                 |         name           |       description
 * ------------------------+------------------------+-----------------------------
 *  4 octets               |       ots index        |  an integer index to a ots
 *  -----------------------+------------------------+-----------------------------
 *  32 octets              |          R             |  used in hashed key
 *  -----------------------+------------------------+-----------------------------
 *  wparams->len*32 octets |         wsig           |  wots signature
 *  -----------------------+------------------------+-----------------------------
 *  h*32 octets            |         auth           |  xmss authentication
 * hashes
 *  -----------------------'------------------------+-----------------------------
 *
 *
 */
int xmss_verify_sig(vec_t qmsg, vec_t qsig, vec_t qpub_key) {

  int ret = 0xff;
  vec_t msg = TOVEC(qmsg);
  vec_t sig = TOVEC(qsig);
  vec_t pub_key = TOVEC(qpub_key);

  if (pub_key.len != 67) 
    return ret;

  size_t h = GET_P1B(pub_key.data[1]) * 2;
  uint8_t hf = GET_HFB(pub_key.data[0]);
  int n = 32;
  int w = 16;

  wots_params wparams = wots_init2(hf, n, w);
  // Extract ots index
  uint32_t idx = ((uint32_t)sig.data[0] << 24) | ((uint32_t)sig.data[1] << 16) |
                 ((uint32_t)sig.data[2] << 8) | sig.data[3];

  if ((size_t)(4 + 32 + (wparams.len + h) * n) != sig.len)
    return ret;

  RETURNIF(
    idx > (uint32_t)pow(2.0,(float)h) - 1,
    ret,
    "invalid ots, %"PRIu32"\n",
    idx
  );
  vec_t *wsig = get_wsig_from_sig(sig, wparams.len * 32);
  vec_t *auth = get_auth_from_sig(sig, h * 32);

  uint8_t hash_key[3 * n];

  vec_t pub_seed = vecmem(pub_key.data + 3 + n, n);

  // Init addresses
  uint32_t ots_addr[8] = {0};
  uint32_t ltree_addr[8] = {0};
  uint32_t node_addr[8] = {0};

  setType(ots_addr, 0);
  setType(ltree_addr, 1);
  setType(node_addr, 2);


  // Generate hash key (R || root || idx)
  memcpy(hash_key, sig.data + 4, n);
  memcpy(hash_key + n, pub_key.data + 3, n);
  to_byte(hash_key + 2 * n, idx, n);

  vec_t msg_h =
      h_msg(&wparams, msg, (vec_t){.data = (void *)hash_key, .len = 3 * n});
  //-----------------------
  // Verify signature
  //-----------------------

  // Prepare Address
  setOTSADRS(ots_addr, idx);
  // Check WOTS signature
  vec_t *wots_pk = wots_pk_from_sig(wsig, msg_h, &wparams, pub_seed, ots_addr);

  // Compute Ltree
  setLtreeADRS(ltree_addr, idx);
  vec_t pkhash = ltree_root(&wparams, wots_pk, pub_seed, ltree_addr);

  vec_t root =
      validate_authpath(&wparams, pkhash, idx, auth, h, pub_seed, node_addr);

  for (size_t i = 0; i < wparams.len; i++) {
    vecfree(wsig[i]);
    vecfree(wots_pk[i]);
  }
  OPENSSL_secure_free(wots_pk);
  OPENSSL_secure_free(wsig);
  for (size_t i = 0; i < h; i++) {
    vecfree(auth[i]);
  }
  OPENSSL_secure_free(auth);
  vecfree(pkhash);
  vecfree(pub_seed);
  vecfree(msg_h);
  if (!memcmp(root.data, pub_key.data + 3, n)) ret ^= ret;

  vecfree(root);

  return ret;
}
