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

#include <openssl/crypto.h>

#include "xmss.h"

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

#define XMSS_ASSERT(x, ...) do {if (!(x)) {LOGF(#x ": " __VA_ARGS__); abort();}} while (0)

/* LOG FORCE */
#  define LOGF(...)                                                        \
    do {                                                                  \
      fprintf(stderr, "%s:%d @ %s(...): ", __FILE__, __LINE__, __func__); \
      fprintf(stderr, __VA_ARGS__);                                       \
    } while (0)

#if !defined(QDEBUG)
#  define LOG(...) \
    do {           \
      ;            \
    } while (0)
#else
#  define LOG(...) LOGF(...)
#endif

#define RETURNIF(cond, ret, ...) \
  do {                           \
    if (cond) {                  \
      LOG(#cond ": " __VA_ARGS__);  \
      return ret;                \
    }                            \
  } while (0)

#define VECDEBUG(x)                                 \
  do {                                              \
    LOG("vec_t " #x " (%zu bytes ...)\n", (x).len); \
    vecdump(x);                                     \
  } while (0)

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline uint32_t tobig_32(uint32_t n) {return n;}
#else
static inline uint32_t tobig_32(uint32_t n) {
  uint32_t a = (n & (uint32_t)0xff000000) >> (3 * 8);
  uint32_t b = (n & (uint32_t)0x00ff0000) >> (1 * 8);
  uint32_t c = (n & (uint32_t)0x0000ff00) << (1 * 8);
  uint32_t d = (n & (uint32_t)0x000000ff) << (3 * 8);
  return a | b | c | d;
}
#endif


static void dump_binary(const char *const data, const size_t len) {
  int space_padding = 50;
  char look_up[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  for (size_t i = 0; i < len; i++) {
    putchar(look_up[(data[i] >> 4) & 0x0f]);
    putchar(look_up[data[i] & 0x0f]);
    putchar(' ');
    space_padding -= 3;
    if (i == 7) {
      putchar(' ');
      space_padding--;
    }
  }
  for (int i = 0; i < space_padding; i++) putchar(' ');
}

static void dump_ascii(const char *const data, const size_t len) {
  int space_padding = 16;
  printf("|");
  for (size_t i = 0; i < len; i++) {
    space_padding--;
    if (data[i] < 0x20) {
      putchar('.');
    } else if (data[i] < 0x7f)
      putchar(data[i]);
    else
      putchar('.');
  }
  for (int i = 0; i < space_padding; i++) putchar(' ');
  printf("|");
}

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
/*
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

static void vecdump(vec_t v) {
  size_t to_write = 16;

  for (const char *cur = v.data; cur != v.data + v.len; cur += to_write) {
    /* make sure we don't overflow */
    if ((size_t)(cur + to_write) > (size_t)(v.data + v.len))
      to_write = (size_t)((v.data + v.len) - cur);

    if (!(cur >= v.data))
      return;

    printf("%08" PRIx32 "  ", (uint32_t)(cur - v.data));
    dump_binary(cur, to_write);
    dump_ascii(cur, to_write);
    puts("");
  }
  //  assert(len == (size_t)(idata - data));
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
static vec_t veccat2(char *fmt, ...);

static vec_t vec2nm(vec_t);

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

/* prints hexdump of v */
static void vecprintx(vec_t v);

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

static vec_t get_seed(hfunc_ctx *hfunc, const vec_t sk_seed, int n,
                      uint32_t addr[8]) {
  unsigned char bytes[32];

  // Make sure that chain addr, hash addr, and key bit are 0!
  setChainADRS(addr, 0);
  setHashADRS(addr, 0);
  setKeyAndMask(addr, 0);

  addr_to_byte(bytes, addr);
  // Generate pseudorandom value
  return prf(hfunc, (vec_t){.data = (void *)bytes, .len = 32}, sk_seed, n);
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

static vec_t *wots_skgen(hfunc_ctx *hfunc, const vec_t inseed, const size_t n,
                          const uint32_t len) {
  vec_t *outseeds = OPENSSL_secure_malloc(sizeof(*outseeds) * len);

  unsigned char ctr[32];
  for (uint32_t i = 0; i < len; i++) {
    to_byte(ctr, i, 32);
    outseeds[i] =
        prf(hfunc, (vec_t){.data = (void *)ctr, .len = 32}, inseed, n);
  }
  return outseeds;
}

/* returns array of wparams->len elements of public keys derived from sk and
 * pub_seed*/
static vec_t *wots_pkgen(const vec_t sk, wots_params *wparams,
                         const vec_t pub_seed, uint32_t addr[8]) {
  vec_t *pk = wots_skgen(&wparams->hfunc, sk, wparams->n, wparams->len);
  for (size_t i = 0; i < wparams->len; i++) {
    setChainADRS(addr, i);
    /* we generate the pkeys chaining skeys we genwrated from wots_skgen*/
    vec_t v = gen_chain(pk[i], 0, wparams->w - 1, wparams, pub_seed, addr);
    vecfree(pk[i]);
    pk[i] = v;
  }

  return pk;
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
static vec_t gen_leaf_wots(const vec_t sk_seed, wots_params *wparams,
                           const vec_t pub_seed, uint32_t ltree_addr[8],
                           uint32_t ots_addr[8]) {
  vec_t seed = get_seed(&wparams->hfunc, sk_seed, wparams->n, ots_addr);
  vec_t *wots_pkeys = wots_pkgen(seed, wparams, pub_seed, ots_addr);

  vec_t root = ltree_root(wparams, wots_pkeys, pub_seed, ltree_addr);

  for (size_t i = 0; i < wparams->len; i++) vecfree(wots_pkeys[i]);
  OPENSSL_secure_free(wots_pkeys);
  vecfree(seed);

  return root;
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

static void vecprintx(vec_t v) {
  for (size_t i = 0; i < v.len; i++)
    printf("%02" PRIx8, (unsigned char)v.data[i]);
  // puts("");
}

inline vec_t veccat(vec_t a, vec_t b) {
  size_t len = a.len + b.len;
  char *data = OPENSSL_secure_malloc(len);
  memcpy(data, a.data, a.len);
  memcpy(data + a.len, b.data, b.len);
  return (vec_t){.data = data, .len = len};
}

/* vec to native mem and frees v */
inline vec_t vec2nm(vec_t v) {
  size_t len = v.len;
  char *data = malloc(len);
  memcpy(data, v.data, v.len);
  vecfree(v);
  return (vec_t){.data = data, .len = len};
}

/* fmt an array of 'v' or 'p'
 * example
 *   veccat2("vv", vec_t, vec_t);
 *   veccat2("pp", size_t, vec_t*, size_t, vec_t*);
 *   veccat2("pv", size_t, vec_t*, vec_t);
 *   veccat2("vp", vec_t, size_t, vec_t*);
 *   veccat2("ppvpvv", size_t, vec_t*, size_t, vec_t*, vec_t, size_t, vec_t *, vec_t, vec_t);
 */
inline vec_t veccat2(char *fmt, ...) {
  size_t len = 0;
  va_list ap;
  vec_t v, *pv;
  size_t n;

  va_start(ap, fmt);

  for (size_t c = 0; fmt[c]; c++) {
    switch (fmt[c]) {
      case 'v':
        v = va_arg(ap, vec_t);
        len += v.len;
        break;
      case 'p':
        n = va_arg(ap, size_t);
        pv = (vec_t *) va_arg(ap, vec_t *);
        for (size_t i = 0; i < n; i++) len += pv[i].len;
        break;
      default:
        XMSS_ASSERT(1, "illegal character %"PRIx8"\n", (uint8_t)fmt[c]);
        break;
    }
  }
  va_end(ap);

  char *data = OPENSSL_secure_malloc(len);
  assert(data != NULL);

  va_start(ap, fmt);
  size_t seek = 0;
  for (size_t c = 0; fmt[c]; c++) {
    switch (fmt[c]) {
      case 'v':
        v = va_arg(ap, vec_t);
        memcpy(data + seek, v.data, v.len);
        seek += v.len;
        break;
      case 'p':
        n = va_arg(ap, size_t);
        pv = va_arg(ap, vec_t *);
        for (size_t i = 0; i < n; i++) {
          memcpy(data + seek, pv[i].data, pv[i].len);
          seek += pv[i].len;
        }
        break;
      default:
        assert(0);
    }
  }
  va_end(ap);
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

/* the generated tree have heights from height-1 (the root) to -1 (the leafs)
 * instead of 0. it's frustrating. If I had the power, the tree would range from
 * `height` to 0 */
static tree_t *tree_alloc(vec_t sk_seed, wots_params *wparams, vec_t pub_seed,
                          int height) {
  typedef struct {
    /* local variables */
    tree_t *t, *ret;
    int height;
    /* caller */
    int caller;
  } pda_args;

  int *treendx = calloc(sizeof(int), height + 3);
  memset(treendx, 0, sizeof(int) * (height + 3));
  /* to account for acessing treendx[-1] */
  treendx += 1;
  size_t ots_ndx = 0;

  size_t nb_calls = 0;
  pda_args arg_calls[height + 2];
  arg_calls[0 /* 0 */].height = height;
  arg_calls[0 /* 0 */].caller = -1;

  while (1) {
    if (arg_calls[nb_calls].height < 0) {
      arg_calls[nb_calls].ret = NULL;
      goto end;
    }
    // printf("alloc height %d\n", height);
    //

    arg_calls[nb_calls].t = OPENSSL_secure_malloc(sizeof(tree_t));
    arg_calls[nb_calls].t->node_height = arg_calls[nb_calls].height - 1;
    arg_calls[nb_calls].t->node_ndx = treendx[arg_calls[nb_calls].height - 1]++;
    arg_calls[nb_calls].t->hash = (vec_t){.data = NULL, .len = 0};

    // push
    nb_calls++;
    arg_calls[nb_calls].height = arg_calls[nb_calls - 1].height - 1;
    arg_calls[nb_calls].caller = 1;
    // call
    continue;
  caller_left:
    // pop
    nb_calls--;
    arg_calls[nb_calls].t->left = arg_calls[nb_calls + 1].ret;
    //    t->left = tree_alloc(sk_seed, wparams, pub_seed, height - 1);

    // push
    nb_calls++;
    arg_calls[nb_calls].height = arg_calls[nb_calls - 1].height - 1;
    arg_calls[nb_calls].caller = 2;
    // call
    continue;
  caller_right:
    // pop
    nb_calls--;
    arg_calls[nb_calls].t->right = arg_calls[nb_calls + 1].ret;
    //    t->right = tree_alloc(sk_seed, wparams, pub_seed, height - 1);

    /* At the very bottom (height == 0),
     * generate our WOTS ltree root */
    if (arg_calls[nb_calls].height == 0) {
      // printf("hit %d\n", ndx_alloc);
      uint32_t ltree_addr[8] = {0};
      setType(ltree_addr, 1);
      setLtreeADRS(ltree_addr, ots_ndx);

      uint32_t ots_addr[8] = {0};
      setType(ots_addr, 0);
      setOTSADRS(ots_addr, ots_ndx++);

      //printf("\rgenerating %zd:%zu/%d", arg_calls[nb_calls].t->node_height,
//             arg_calls[nb_calls].t->node_ndx,
//             (int)pow(2.0, (double)height) - 1);
      //fflush(stdout);
      arg_calls[nb_calls].t->hash =
          gen_leaf_wots(sk_seed, wparams, pub_seed, ltree_addr, ots_addr);
      // fprintf(stdout, "height 0 hit seed: \n");
      // VECDEBUF(t->hash);
      // vecfree(seedh);
    }
    arg_calls[nb_calls].ret = arg_calls[nb_calls].t;

  end:
    if (nb_calls) {
      switch (arg_calls[nb_calls].caller) {
        case 1:
          goto caller_left;
        case 2:
          goto caller_right;
        default:
          XMSS_ASSERT(1, "must have been the cosmic rays\n");
      }
    }
    break;
  }
  //puts("");

  return arg_calls[0].t;
}

static void tree_free(tree_t *t) {
  if (t == NULL)
    return;
  vecfree(t->hash);
  if (t->left != NULL) tree_free(t->left);
  if (t->right != NULL) tree_free(t->right);
  OPENSSL_secure_free(t);
}

/* recursively performs hash calculation on tree */
static vec_t tree_hash(tree_t *t, wots_params *wparams, const vec_t pub_seed) {
  /* recursive calls are simulated as a push down automata with
   * a stack to record it's previous caller.
   *
   * This implementation is specfic to this and would have yield the same
   * hash in an actual recursive call but with fewer lines of code.
   */

  uint32_t n = wparams->n;
  uint8_t catted[2 * n];
  typedef struct {
    /* argument */
    tree_t *t;
    /* local variables */
    vec_t left_hash, right_hash, ret;
    /* caller */
    int caller;
  } pda_args;

  size_t nb_calls = 0;
  pda_args arg_calls[t->node_height + 2];
  arg_calls[0 /* 0 */].t = t;
  arg_calls[0 /* 0 */].caller = -1;

  while (1) {
    XMSS_ASSERT(nb_calls < (size_t)t->node_height + 2, "this must have never happened %zu < %zu\n", nb_calls, (size_t)t->node_height + 2);

    // printf("height %zu\n", arg_calls[nb_calls].t->height);
    if (arg_calls[nb_calls].t->node_height == -1) {
      arg_calls[nb_calls].ret = arg_calls[nb_calls].t->hash;
      goto end;
      // return t->hash;
    }

    // push
    nb_calls++;
    arg_calls[nb_calls].t = arg_calls[nb_calls - 1].t->left;
    arg_calls[nb_calls].caller = 1;
    // call
    continue;
  caller_left_hash:
    // pop
    nb_calls--;
    arg_calls[nb_calls].left_hash = arg_calls[nb_calls + 1].ret;
    // vec_t left_hash = get_hash(t->left, wparams, pub_seed);

    // push
    nb_calls++;
    arg_calls[nb_calls].t = arg_calls[nb_calls - 1].t->right;
    arg_calls[nb_calls].caller = 2;
    // call;
    continue;
  caller_right_hash:
    // pop
    nb_calls--;
    arg_calls[nb_calls].right_hash = arg_calls[nb_calls + 1].ret;
    // vec_t right_hash = get_hash(t->right, wparams, pub_seed);

    memcpy(catted, arg_calls[nb_calls].left_hash.data, n);
    memcpy(catted + n, arg_calls[nb_calls].right_hash.data, n);
    //    vec_t catted =
    //        veccat(arg_calls[nb_calls].left_hash,
    //        arg_calls[nb_calls].right_hash);
    // VECDEBUG(catted);

    uint32_t node_addr[8] = {0};
    setType(node_addr, 2);
    setTreeHeight(node_addr, arg_calls[nb_calls].t->node_height);
    setTreeIndex(node_addr, arg_calls[nb_calls].t->node_ndx);
    //    LOG("treeheight %zd treendx %zu\n",
    //    arg_calls[nb_calls].t->node_height,
    //        arg_calls[nb_calls].t->node_ndx);

    arg_calls[nb_calls].t->hash =
        hash_h(&wparams->hfunc, (vec_t){.data = (void *)catted, .len = 2 * n},
               pub_seed, node_addr, wparams->n);
    // t->hash = hash_h(catted, pub_seed, node_addr, wparams->n);
    // vecfree(catted);
    arg_calls[nb_calls].ret = arg_calls[nb_calls].t->hash;
    // return t->hash;

  end:
    if (nb_calls) {
      switch (arg_calls[nb_calls].caller) {
        case 1:
          goto caller_left_hash;
        case 2:
          goto caller_right_hash;
        default:
          XMSS_ASSERT(1, "must have been the cosmic rays\n");
          break;
      }
    }
    break;
  }
  return arg_calls[0].ret;
}

static void print_tree(tree_t *t) {
  if (t == NULL) return;
  printf("mheight %zd:%zu\n", t->node_height, t->node_ndx);
  //  VECDEBUG(t->hash);
  if (t->left != NULL) {
    printf("\"");
    vecprintx(t->hash);
    printf("\" -> \"");
    vecprintx(t->left->hash);
    puts("\"");
    // printf("\"%p\" -> \"%p\"\n", (void*)t, (void*)t->left);
  }
  if (t->right != NULL) {
    printf("\"");
    vecprintx(t->hash);
    printf("\" -> \"");
    vecprintx(t->right->hash);
    puts("\"");
    // printf("\"%p\" -> \"%p\"\n", (void*)t, (void*)t->right);
  }
  // vecprintx(t->hash);
  print_tree(t->left);
  print_tree(t->right);
}

static tree_t *tree_generate(vec_t sk_seed, wots_params *wparams,
                             vec_t pub_seed, size_t height) {
  tree_t *t = tree_alloc(sk_seed, wparams, pub_seed, height);
  (void)tree_hash(t, wparams, pub_seed);
  return t;
}

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
      XMSS_ASSERT(1, "invalid hf\n");
      abort();
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

static vec_t *get_auth_from_tree(tree_t *mtree, uint32_t ots) {
  assert(mtree->node_height + 1 < 24 &&  mtree->node_height > 0);
  uint32_t h = mtree->node_height + 1 ;
  uint32_t mask = (uint32_t)1 << (h-1);
  uint32_t bits = ots; 
  vec_t *auth = OPENSSL_secure_malloc(sizeof(*auth)*h);

  /* auth traversal by flipping bits */
  for (uint32_t i = 0; i < h; i++) {
    if (mask & bits) {
      auth[(h-1) - i] = veccpy(mtree->left->hash);
      mtree = mtree->right;
    }
    else {
      auth[(h-1) - i] = veccpy(mtree->right->hash);
      mtree = mtree->left;
    }
    assert(mtree != NULL);
    mask >>= 1;
  }

  return auth;
}

static vec_t *wots_sign(vec_t msg, vec_t sk, wots_params *wparams, vec_t pub_seed,
                 uint32_t addr[8]) {
  assert(msg.len == wparams->n);
  int basew[wparams->len];
  int csum = 0;
  uint32_t i = 0;

  base_w(basew, wparams->len_1, (void *)msg.data, wparams);

  for (i = 0; i < wparams->len_1; i++) {
    csum += wparams->w - 1 - basew[i];
  }

  csum = csum << (8 - ((wparams->len_2 * wparams->log_w) % 8));

  uint32_t len_2_bytes = ((wparams->len_2 * wparams->log_w) + 7) / 8;

  unsigned char csum_bytes[len_2_bytes];
  to_byte(csum_bytes, csum, len_2_bytes);

  int csum_basew[wparams->len_2];

  base_w(csum_basew, wparams->len_2, csum_bytes, wparams);

  for (i = 0; i < wparams->len_2; i++) {
    basew[wparams->len_1 + i] = csum_basew[i];
  }

  vec_t *sig = wots_skgen(&wparams->hfunc, sk, wparams->n, wparams->len);
  vec_t *pk = OPENSSL_secure_malloc(sizeof(*pk) * wparams->len);

  for (i = 0; i < wparams->len; i++) {
    setChainADRS(addr, i);
    pk[i] = gen_chain(sig[i], 0, basew[i], wparams, pub_seed, addr);
    vecfree(sig[i]);
  }
  OPENSSL_secure_free(sig);

  return pk;
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

int xmss_secure_heap_init() {
  /* 16 is some magic number we check if secure heap has been init. */
  /* the usual number returned by CRYPTO_secure_malloc_init() range
   * from 0 to 2
   */
  return CRYPTO_secure_malloc_initialized() ? 16 :
    CRYPTO_secure_malloc_init(1 << 17, 0);
}

/* compat */
int xmss_secure_heap_release() {
  return CRYPTO_secure_malloc_initialized() ?
    CRYPTO_secure_malloc_done() : 16;
}

vec_t xmss_pubkey_to_pubaddr(vec_t pubkey) {
  if (pubkey.len != 67)
    return VEC_NULL;

  vec_t t1 =
      vechash_sha256((vec_t){.data = (void *)pubkey.data, .len = pubkey.len});
  vec_t t2 = vecmalloc(3 + 32);
  /* copy 3 bytes qrl address descriptor */
  memcpy(t2.data, pubkey.data, 3);
  /* copy 32 bytes hashed public key */
  memcpy(t2.data + 3, t1.data, 32);
  vec_t t3 = vechash_sha256(t2);
  /* 4 bytes verification hash */
  vec_t t4 = vecmem(t3.data + t3.len - 4, 4);

  vec_t pubaddr = veccat(t2, t4);
  vecfree(t1);
  vecfree(t2);
  vecfree(t3);
  vecfree(t4);
  return vec2nm(pubaddr);;
}

vec_t xmss_gen_pubkey(vec_t hexseed) {
  assert(hexseed.len == 51);
  int n = 32;
  int w = 16;
  wots_params wparams;
  uint8_t sig = GET_SIGB(hexseed.data[0]);
  uint8_t hf = GET_HFB(hexseed.data[0]);
  uint8_t af = GET_AFB(hexseed.data[1]);
  uint8_t height = GET_P1B(hexseed.data[1]) * 2;
  /* XMSS */
  RETURNIF(
    sig != 0,
    VEC_NULL,
    "invalid sig type\n"
  );
  /* HF */
  wparams = wots_init2(hf, n, w);
  /* AF: SHA2_256X */
  RETURNIF(
    af != 0,
    VEC_NULL,
    "invalid af type\n"
  );

  vec_t seed = vecmem(hexseed.data + 3, 48);

  /* randbytes format (96 octets):
   *
   *    size          |         name            |       description
   * -----------------+-------------------------+----------------------------
   *    32 octets     |       sk_seed           |
   * -----------------+-------------------------+----------------------------
   *    32 octets     |       sk_prf            |      Maybe unused?
   * -----------------+-------------------------+----------------------------
   *    32 octets     |       pub_seed          |
   */
  vec_t randbytes = vechash_shake256(seed, 96 /* 3*32 */);
  // VECDEBUG(randbytes);

  vec_t sk_seed = vecmem(randbytes.data, 32);
  // VECDEBUG(sk_seed);

  /* unused */
  //  vec_t sk_prf = vecmalloc(32);
  //  memcpy(sk_prf.data, randbytes.data + 32, 32);

  vec_t pub_seed = vecmem(randbytes.data + 64, 32);
  // VECDEBUG(pub_seed);

  tree_t *mtree = tree_generate(sk_seed, &wparams, pub_seed, height);

  /* pub_key format (67 octets)
   *    size          |         name            |       description
   * -----------------+-------------------------+----------------------------
   *  3 octets        |      qrl addr desc      |  QRL  address descriptor
   *  ----------------+-------------------------+----------------------------
   *  32 octets       |         root            |       XMSS root
   *  ------------------------------------------+----------------------------
   *  32 octets       |       pub seed          |       public seed
   */
  vec_t pub_key = veccat2("vvv", (vec_t){.data = (void*)hexseed.data, .len=3}, mtree->hash, pub_seed);

  tree_free(mtree);
  vecfree(seed);
  vecfree(randbytes);
  vecfree(sk_seed);
  vecfree(pub_seed);

  return vec2nm(pub_key);
}


vec_t xmss_sign_msg(vec_t qhexseed, vec_t qmsg, uint32_t ots) {
  int is_mem_init = xmss_secure_heap_init();
  assert(is_mem_init != 0);
  assert(qhexseed.len == 51);
  wots_params wparams;
  vec_t hexseed = TOVEC(qhexseed);
  vec_t msg = TOVEC(qmsg);
  assert(hexseed.len == 51);
  int n = 32;
  int w = 16;
  uint8_t hf = GET_HFB(hexseed.data[0]);
  uint8_t af = GET_AFB(hexseed.data[1]);
  uint8_t height = GET_P1B(hexseed.data[1]) * 2;
  RETURNIF(
    ots > (uint32_t)pow(2.0,(float)height) - 1,
    VEC_NULL,
    "invalid ots, %d\n",
    ots
  );

  {
    /* XMSS */
    uint8_t sig = GET_SIGB(hexseed.data[0]);
    RETURNIF(
      sig != 0,
      VEC_NULL,
      "invalid sig type\n"
    );
  }
  /* HF */
  wparams = wots_init2(hf, n, w);
  /* AF: SHA2_256X */
  assert(af == 0);

  vec_t seed = vecmem(hexseed.data + 3, 48);

  /* randbytes format (96 octets):
   *
   *    size          |         name            |       description
   * -----------------+-------------------------+----------------------------
   *    32 octets     |       sk_seed           |
   * -----------------+-------------------------+----------------------------
   *    32 octets     |       sk_prf            |      Maybe unused?
   * -----------------+-------------------------+----------------------------
   *    32 octets     |       pub_seed          |
   */
  vec_t randbytes = vechash_shake256(seed, 96 /* 3*32 */);
  // VECDEBUG(randbytes);

  vec_t sk_seed = vecmem(randbytes.data, 32);
  // VECDEBUG(sk_seed);

  vec_t sk_prf = vecmem(randbytes.data + 32, 32);
  // VECDEBUG(sk_prf);

  vec_t pub_seed = vecmem(randbytes.data + 64, 32);
  // VECDEBUG(pub_seed);
  //

  tree_t *mtree = tree_generate(sk_seed, &wparams, pub_seed, height);

  uint32_t idx = ots;

  // index as 32 bytes string
  uint8_t idx_bytes_32[32];
  to_byte(idx_bytes_32, idx, 32);

  uint8_t hash_key[3 * n];

  // -- Secret key for this non-forward-secure version is now updated.
  // -- A productive implementation should use a file handle instead and write
  // the updated secret key at this point!
  uint32_t ots_addr[8] = {0};

  // ---------------------------------
  // Message Hashing
  // ---------------------------------

  // First compute pseudorandom value
  vec_t R = prf(&wparams.hfunc, (vec_t){.data = (void *)idx_bytes_32, .len = n},
                sk_prf, n);
  // Generate hash key (R || root || idx)
  memcpy(hash_key, R.data, n);
  memcpy(hash_key + n, mtree->hash.data, n);
  to_byte(hash_key + 2 * n, idx, n);
  // Then use it for message digest
  vec_t msg_h =
      h_msg(&wparams, msg, (vec_t){.data = (void *)hash_key, .len = 3 * n});

  // ----------------------------------
  // Now we start to "really sign"
  // ----------------------------------

  // Prepare Address
  setType(ots_addr, 0);
  setOTSADRS(ots_addr, idx);

  // Compute seed for OTS key pair
  vec_t ots_seed = get_seed(&wparams.hfunc, sk_seed, n, ots_addr);

  // Compute WOTS signature
  vec_t *wsig = wots_sign(msg_h, ots_seed, &wparams, pub_seed, ots_addr);

  vec_t *auth = get_auth_from_tree(mtree, ots);
  vecfree(seed);
  vecfree(sk_seed);
  vecfree(sk_prf);
  vecfree(pub_seed);
  vecfree(ots_seed);
  /*
   * sig format:
   *
   *    size                 |         name           |       description
   * ------------------------+------------------------+-----------------------------
   *  4 octets               | ots index (big endian) |  an integer ots
   *  -----------------------+------------------------+-----------------------------
   *  32 octets              |          R             |  used in hashed key
   *  -----------------------+------------------------+-----------------------------
   *  wparams->len*32 octets |         wsig           |  wots signature
   *  -----------------------+------------------------+-----------------------------
   *  h*32 octets            |         auth           |  xmss authentication hashes
   *  -----------------------'------------------------+-----------------------------
   *
   *
   */
  vec_t sig = veccat2("vvpp",
      (vec_t){.data = (void *)&(uint32_t){tobig_32(idx)}, .len = sizeof(uint32_t)},
      R,
      (size_t)wparams.len,
      wsig,
      (size_t)height,
      auth
  );
  assert((size_t)(4 + 32 + (wparams.len + height) * wparams.n) == sig.len);
  vecfree(R);
  for (uint32_t i = 0; i < wparams.len; i++) vecfree(wsig[i]);
  OPENSSL_secure_free(wsig);
  for (ssize_t i = 0; i < height; i++) vecfree(auth[i]);
  OPENSSL_secure_free(auth);
  tree_free(mtree);

  if (is_mem_init == 1 || is_mem_init == 2)
    xmss_secure_heap_release();
  return vec2nm(sig);
}

xmss_tree_t *xmss_gen_tree(vec_t qhexseed) {
  xmss_tree_t *xtree = OPENSSL_secure_malloc(sizeof(*xtree));
  if (xtree == NULL) {
    abort();
  }

  vec_t hexseed = TOVEC(qhexseed);
  assert(hexseed.len == 51);
  int n = 32;
  int w = 16;
  uint8_t hf = GET_HFB(hexseed.data[0]);
  uint8_t af = GET_AFB(hexseed.data[1]);
  uint8_t height = GET_P1B(hexseed.data[1]) * 2;

  xtree->wparams = OPENSSL_secure_malloc(sizeof(*(xtree->wparams)));
  *(xtree->wparams) = wots_init2(hf, n, w);
  /* AF: SHA2_256X */
  if (af != 0) {
    LOG("invalid af\n");
    return NULL;
  }

  vec_t seed = vecmem(hexseed.data + 3, 48);

  /* randbytes format (96 octets):
   *
   *    size          |         name            |       description
   * -----------------+-------------------------+----------------------------
   *    32 octets     |       sk_seed           |
   * -----------------+-------------------------+----------------------------
   *    32 octets     |       sk_prf            |      Maybe unused?
   * -----------------+-------------------------+----------------------------
   *    32 octets     |       pub_seed          |
   */
  vec_t randbytes = vechash_shake256(seed, 96 /* 3*32 */);
  // VECDEBUG(randbytes);

  vec_t sk_seed = vecmem(randbytes.data, 32);
  // VECDEBUG(sk_seed);

  vec_t sk_prf = vecmem(randbytes.data + 32, 32);
  // VECDEBUG(sk_prf);

  vec_t pub_seed = vecmem(randbytes.data + 64, 32);
  // VECDEBUG(pub_seed);
  //

  tree_t *mtree = tree_generate(sk_seed, xtree->wparams, pub_seed, height);
  xtree->tree = mtree;
  xtree->sk_seed = sk_seed;
  xtree->sk_prf = sk_prf;
  xtree->pub_seed = pub_seed;
  //xtree->sig = sig;
  xtree->hf = hf;
  xtree->p1 = GET_P1B(hexseed.data[1]);
  vecfree(seed);
  vecfree(randbytes);
  return xtree;
}

void xmss_tree_free(xmss_tree_t *ctx) {
  tree_free(ctx->tree);
  OPENSSL_secure_free(ctx->wparams);
  vecfree(ctx->sk_seed);
  vecfree(ctx->sk_prf);
  vecfree(ctx->pub_seed);
  OPENSSL_secure_free(ctx);
}

vec_t xmss_tree_pubkey(const xmss_tree_t *ctx) {
  vec_t pub_seed = ctx->pub_seed;
  vec_t xpub = ctx->tree->hash;
/* QRL address descriptor layout DESC (24 bits). */
/*------------------------------------------------.
|  4 bits |  4 bits  | 4 bits |  4 bits  | 8 bits |
|    SIG  |     HF   |   AF   |    P1    |   P2   |
`------------------------------------------------*/
/* 23 bit <-------------------------------- 0 bit */
  uint8_t desc[]  = {(0 << 4) | ctx->hf, 0 | ctx->p1, 0};
  vec_t pub_key = veccat2("vvv", (vec_t){.data = (void*)desc, .len=3}, xpub, pub_seed);
  return vec2nm(pub_key);
}

vec_t xmss_tree_pubaddr(const xmss_tree_t *ctx) {
  vec_t pub_key = xmss_tree_pubkey(ctx);

  if (pub_key.len != 67)
    return VEC_NULL;

  vec_t t1 =
      vechash_sha256((vec_t){.data = (void *)pub_key.data, .len = pub_key.len});
  vec_t t2 = vecmalloc(3 + 32);
  /* copy 3 bytes qrl address descriptor */
  memcpy(t2.data, pub_key.data, 3);
  /* copy 32 bytes hashed public key */
  memcpy(t2.data + 3, t1.data, 32);
  vec_t t3 = vechash_sha256(t2);
  /* 4 bytes verification hash */
  vec_t t4 = vecmem(t3.data + t3.len - 4, 4);

  vec_t pub_addr = veccat(t2, t4);
  vecfree(t1);
  vecfree(t2);
  vecfree(t3);
  vecfree(t4);
  return vec2nm((vec_t){.data = (void *)pub_addr.data, .len = pub_addr.len});
}

vec_t xmss_tree_sign_msg(const xmss_tree_t *mtree, vec_t qmsg, uint32_t ots) {
  int is_mem_init = xmss_secure_heap_init();
  assert(is_mem_init != 0);

  wots_params wparams = *(mtree->wparams);
  vec_t msg = TOVEC(qmsg);
  size_t n = 32;

  uint8_t height = mtree->p1 * 2;
  RETURNIF(
    ots > (uint32_t)pow(2.0,(float)height) - 1,
    VEC_NULL,
    "invalid ots, %"PRIu32"\n",
    ots
  );

  vec_t sk_seed = mtree->sk_seed;
  // VECDEBUG(sk_seed);

  vec_t sk_prf = mtree->sk_prf;
  // VECDEBUG(sk_prf);

  vec_t pub_seed = mtree->pub_seed;
  // VECDEBUG(pub_seed);
  //

  uint32_t idx = ots;

  // index as 32 bytes string
  uint8_t idx_bytes_32[32];
  to_byte(idx_bytes_32, idx, 32);

  uint8_t hash_key[3 * n];

  // -- Secret key for this non-forward-secure version is now updated.
  // -- A productive implementation should use a file handle instead and write
  // the updated secret key at this point!
  uint32_t ots_addr[8] = {0};

  // ---------------------------------
  // Message Hashing
  // ---------------------------------

  // First compute pseudorandom value
  vec_t R = prf(&wparams.hfunc, (vec_t){.data = (void *)idx_bytes_32, .len = n},
                sk_prf, n);
  // Generate hash key (R || root || idx)
  memcpy(hash_key, R.data, n);
  memcpy(hash_key + n, mtree->tree->hash.data, n);
  to_byte(hash_key + 2 * n, idx, n);
  // Then use it for message digest
  vec_t msg_h =
      h_msg(&wparams, msg, (vec_t){.data = (void *)hash_key, .len = 3 * n});

  // ----------------------------------
  // Now we start to "really sign"
  // ----------------------------------

  // Prepare Address
  setType(ots_addr, 0);
  setOTSADRS(ots_addr, idx);

  // Compute seed for OTS key pair
  vec_t ots_seed = get_seed(&wparams.hfunc, sk_seed, n, ots_addr);

  // Compute WOTS signature
  vec_t *wsig = wots_sign(msg_h, ots_seed, &wparams, pub_seed, ots_addr);

  vec_t *auth = get_auth_from_tree(mtree->tree, ots);
  vecfree(ots_seed);
  /*
   * sig format:
   *
   *    size                 |         name           |       description
   * ------------------------+------------------------+-----------------------------
   *  4 octets               | ots index (big endian) |  an integer ots
   *  -----------------------+------------------------+-----------------------------
   *  32 octets              |          R             |  used in hashed key
   *  -----------------------+------------------------+-----------------------------
   *  wparams->len*32 octets |         wsig           |  wots signature
   *  -----------------------+------------------------+-----------------------------
   *  h*32 octets            |         auth           |  xmss authentication hashes
   *  -----------------------'------------------------+-----------------------------
   *
   *
   */
  vec_t sig = veccat2("vvpp",
      (vec_t){.data = (void *)&(uint32_t){tobig_32(idx)}, .len = sizeof(uint32_t)},
      R,
      (size_t)wparams.len,
      wsig,
      (size_t)height,
      auth
  );
  assert((size_t)(4 + 32 + (wparams.len + height) * wparams.n) == sig.len);
  vecfree(R);
  for (uint32_t i = 0; i < wparams.len; i++) vecfree(wsig[i]);
  OPENSSL_secure_free(wsig);
  for (ssize_t i = 0; i < height; i++) vecfree(auth[i]);
  OPENSSL_secure_free(auth);

  if (is_mem_init == 1 || is_mem_init == 2)
    xmss_secure_heap_release();
  return vec2nm(sig);
}
