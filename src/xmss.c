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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define LOG(...)                                                        \
  do {                                                                  \
    fprintf(stderr, "%s:%d @ %s(...): ", __FILE__, __LINE__, __func__); \
    fprintf(stderr, __VA_ARGS__);                                       \
  } while (0)

#define VECDEBUG(x)                                 \
  do {                                              \
    LOG("vec_t " #x " (%zu bytes ...)\n", (x).len); \
    vecdump(x);                                     \
  } while (0)

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
typedef struct vec_t vec_t;
struct vec_t {
  size_t len;
  char *data;
};

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

    assert(cur >= v.data);
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
    assert(0);
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

static vec_t *expand_seed(hfunc_ctx *hfunc, const vec_t inseed, const size_t n,
                          const uint32_t len) {
  vec_t *outseeds = malloc(sizeof(*outseeds) * len);

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
  vec_t *pk = expand_seed(&wparams->hfunc, sk, wparams->n, wparams->len);
  for (size_t i = 0; i < wparams->len; i++) {
    setChainADRS(addr, i);
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
  free(wots_pkeys);
  vecfree(seed);

  return root;
}

inline vec_t vecmem(void *mem, size_t len) {
  char *data = malloc(len);
  memcpy(data, mem, len);
  return (vec_t){.data = data, .len = len};
}

inline vec_t veccpy(vec_t v) {
  char *data = malloc(v.len);
  memcpy(data, v.data, v.len);
  return (vec_t){.data = data, .len = v.len};
}

inline void vecfree(vec_t v) { free(v.data); }

static vec_t vecmalloc(size_t len) {
  char *data = malloc(len);
  assert(data != NULL);
  return (vec_t){.data = data, .len = len};
}

static void vecprintx(vec_t v) {
  for (size_t i = 0; i < v.len; i++)
    printf("%02" PRIx8, (unsigned char)v.data[i]);
  // puts("");
}

inline vec_t veccat(vec_t a, vec_t b) {
  size_t len = a.len + b.len;
  char *data = malloc(len);
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
  assert(mdctx != NULL);
  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
    assert(0);
  }

  if (EVP_DigestUpdate(mdctx, (void *)msg.data, msg.len) != 1) {
    assert(0);
  }

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
  assert(mdctx != NULL);
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
  assert(mdctx != NULL);
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

    arg_calls[nb_calls].t = malloc(sizeof(tree_t));
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

      printf("\rgenerating %zd:%zu/%d", arg_calls[nb_calls].t->node_height,
             arg_calls[nb_calls].t->node_ndx,
             (int)pow(2.0, (double)height) - 1);
      fflush(stdout);
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
          LOG("must have been the cosmic rays\n");
          assert(0);
      }
    }
    break;
  }
  puts("");

  return arg_calls[0].t;
}

static void tree_free(tree_t *t) {
  vecfree(t->hash);
  if (t->left != NULL) tree_free(t->left);
  if (t->right != NULL) tree_free(t->right);
  free(t);
}

/* recursively performs hash calculation on tree */
static vec_t tree_hash(tree_t *t, wots_params *wparams, const vec_t pub_seed) {
  /* recursive calls are simulated as a push down automata with
   * a stack to record it's previous caller.
   *
   * This implementation is specfic to this and would have yield the same
   * hash in an actual recursive call but with fewer lines of code.
   */

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
    /* it's better to crash than silently overflowing */
    if (nb_calls >= (size_t)t->node_height + 2) {
      LOG("this must have never happened\n");
      assert(0);
    }
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

    vec_t catted =
        veccat(arg_calls[nb_calls].left_hash, arg_calls[nb_calls].right_hash);
    // VECDEBUG(catted);

    uint32_t node_addr[8] = {0};
    setType(node_addr, 2);
    setTreeHeight(node_addr, arg_calls[nb_calls].t->node_height);
    setTreeIndex(node_addr, arg_calls[nb_calls].t->node_ndx);
    //    LOG("treeheight %zd treendx %zu\n",
    //    arg_calls[nb_calls].t->node_height,
    //        arg_calls[nb_calls].t->node_ndx);

    arg_calls[nb_calls].t->hash =
        hash_h(&wparams->hfunc, catted, pub_seed, node_addr, wparams->n);
    // t->hash = hash_h(catted, pub_seed, node_addr, wparams->n);
    vecfree(catted);
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
          LOG("must have been the cosmic rays\n");
          assert(0);
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

#include "include/types.h"

#define TOVEC(q) \
  (vec_t) { .data = (void *)q.data, .len = q.len }

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

qvec_t xmss_pubkey_to_pubaddr(qvec_t pubkey) {
  assert(pubkey.len == 67);
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
  return (qvec_t){.data = (void *)pubaddr.data, .len = pubaddr.len};
}

static wots_params wots_init2(uint8_t hf, size_t digest_len, int n, int w) {
  switch (hf) {
    case 0:
      return wots_init(
          (hfunc_ctx){.digest_len = digest_len, .hfunc = hfunc_sha256}, n, w);
    case 1:
      return wots_init(
          (hfunc_ctx){.digest_len = digest_len, .hfunc = hfunc_shake128}, n, w);
    case 2:
      return wots_init(
          (hfunc_ctx){.digest_len = digest_len, .hfunc = hfunc_shake256}, n, w);
    default:
      assert(0);
  }
}

qvec_t xmss_gen_pubkey(qvec_t hexseed) {
  assert(hexseed.len == 51);
  int n = 32;
  int w = 16;
  wots_params wparams;
  uint8_t sig = GET_SIGB(hexseed.data[0]);
  uint8_t hf = GET_HFB(hexseed.data[0]);
  uint8_t af = GET_AFB(hexseed.data[1]);
  uint8_t height = GET_P1B(hexseed.data[1]) * 2;
  /* XMSS */
  assert(sig == 0);
  /* HF */
  wparams = wots_init2(hf, 32, n, w);
  /* AF: SHA2_256X */
  assert(af == 0);

  vec_t seed = vecmem(hexseed.data + 3, 48);
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
  /* pub_key (67 bytes) = [ QRL addr desc (3 bytes) || merkle root (32 bytes) ||
   * pub_seed (32 bytes) ] */
  qvec_t pub_key = qrl_qvecmalloc(67);
  memcpy(pub_key.data, hexseed.data, 3);
  memcpy(pub_key.data + 3, mtree->hash.data, 32);
  memcpy(pub_key.data + 3 + 32, pub_seed.data, 32);

  tree_free(mtree);
  vecfree(seed);
  vecfree(randbytes);
  vecfree(sk_seed);
  vecfree(pub_seed);
  return pub_key;
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
  vec_t *pk = malloc(sizeof(*pk) * XMSS_WOTS_LEN);
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
  vec_t *ret = malloc(sizeof(*ret) * nb);
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

/* pub_key format (67 bytes):
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
 *    size          |         name           |       description
 * -----------------+------------------------+-----------------------------
 *  4 octets        |       ots index        |  an integer index to a ots
 *  ----------------+------------------------+-----------------------------
 *  32 octets       |          R             |  used in hashed key
 *  ----------------+------------------------+-----------------------------
 *  wparams->len*32 |         wsig           |  wots signature
 *  ----------------+------------------------+-----------------------------
 *  h*32            |         auth           |  xmss authentication hashes
 *  ----------------'------------------------+-----------------------------
 *
 * pub_key (67 bytes): [qrl addr desc (3 bytes) || root (32 bytes) || pub_seed
 * (32 bytes)
 *
 */
int xmss_verify_sig(qvec_t msg, qvec_t sig, qvec_t pub_key) {
  assert(msg.len == 32);
  assert(pub_key.len == 67);
  int ret = 0xff;
  size_t h = GET_P1B(pub_key.data[1]) * 2;
  uint8_t hf = GET_HFB(pub_key.data[0]);
  int n = 32;
  int w = 16;

  wots_params wparams = wots_init2(hf, 32, n, w);
  assert((size_t)(4 + 32 + wparams.len * 32 + h * 32) == sig.len);
  vec_t *wsig = get_wsig_from_sig(TOVEC(sig), wparams.len * 32);
  vec_t *auth = get_auth_from_sig(TOVEC(sig), h * 32);

  uint8_t hash_key[3 * n];

  vec_t pub_seed = vecmem(pub_key.data + 3 + n, n);

  // Init addresses
  uint32_t ots_addr[8] = {0};
  uint32_t ltree_addr[8] = {0};
  uint32_t node_addr[8] = {0};

  setType(ots_addr, 0);
  setType(ltree_addr, 1);
  setType(node_addr, 2);

  // Extract ots index
  uint32_t idx = ((uint32_t)sig.data[0] << 24) | ((uint32_t)sig.data[1] << 16) |
                 ((uint32_t)sig.data[2] << 8) | sig.data[3];

  // Generate hash key (R || root || idx)
  memcpy(hash_key, sig.data + 4, n);
  memcpy(hash_key + n, pub_key.data + 3, n);
  to_byte(hash_key + 2 * n, idx, n);

  // h_msg(msg_h, sig_msg + tmp_sig_len, m_len, hash_key, 3*n, n);
  vec_t msg_h = h_msg(&wparams, TOVEC(msg),
                      (vec_t){.data = (void *)hash_key, .len = 3 * n});
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
  free(wots_pk);
  free(wsig);
  for (size_t i = 0; i < h; i++) {
    vecfree(auth[i]);
  }
  free(auth);
  vecfree(pkhash);
  vecfree(pub_seed);
  vecfree(msg_h);
  if (!memcmp(root.data, pub_key.data + 3, n)) ret ^= ret;

  vecfree(root);
  ;
  return ret;
}

static int noopmain() {
  qvec_t hexseed = {
      .data = (char[]){0x00, 0x05, 0x00, 0x5c, 0x4c, 0x67, 0x64, 0x50, 0x4c,
                       0x48, 0xba, 0x31, 0xe9, 0x36, 0x30, 0x71, 0x98, 0x42,
                       0xb4, 0xaf, 0x9a, 0xab, 0xf6, 0x9a, 0x8b, 0x1a, 0xea,
                       0xe3, 0x60, 0x6d, 0xce, 0xd8, 0x98, 0xd6, 0x8e, 0xc3,
                       0x1e, 0x3a, 0x35, 0xee, 0x7e, 0xe6, 0xc3, 0x8a, 0xf7,
                       0xfe, 0xe5, 0x9e, 0xab, 0xb1, 0x36},
      .len = 51};

  /* randbits (96 bytes) = [sk_seed (32 bytes) || sk_prf (32 bytes) || pub_seed
   * (32 bytes)] */
  vecprintx(*(vec_t *)&hexseed);
  qvec_t pub_key = xmss_gen_pubkey(hexseed);
  // VECDEBUG(*(vec_t*)&pub_key);
  //   puts("");
  //  vec_t randbits = vechash_shake256(hexseed, 96 /* 3*32 */);
  //  VECDEBUG(randbits);
  //  puts("");
  //
  //  vec_t sk_seed = vecmalloc(32);
  //  memcpy(sk_seed.data, randbits.data, 32);
  //  VECDEBUG(sk_seed);
  //
  //  vec_t sk_prf = vecmalloc(32);
  //  memcpy(sk_prf.data, randbits.data + 32, 32);
  //
  //  vec_t pub_seed = vecmalloc(32);
  //  memcpy(pub_seed.data, randbits.data + 64, 32);
  //  VECDEBUG(pub_seed);
  //
  //  tree_t *mtree = tree_generate(sk_seed, &wparams, pub_seed, 10);
  //  vec_t pk = vecmalloc(67);
  //  memcpy(pk.data, qaddr, 3);
  //  memcpy(pk.data + 3, mtree->hash.data, 32);
  //  memcpy(pk.data + 3 + 32, pub_seed.data, 32);
  //  VECDEBUG(pk);
  //
  //  vec_t hashed = vechash_sha256(pk);
  //  VECDEBUG(hashed);
  // vec_t ltree_root = gen_leaf_wots(sk_seed, &wparams, pub_seed, ltree_addr,
  // ots_addr); vecprintx(ltree_root); puts("");
  //  wots_pkgen(hash_func, pk, seed, &(params->wots_par), pub_seed, ots_addr);
  //
  //  l_tree(hash_func, &params->wots_par, leaf, pk, pub_seed, ltree_addr);
  //  vec_t *wots_pk = wots_pkgen(sk, params
  // vecprintx(randbits);

  return 0;
}
