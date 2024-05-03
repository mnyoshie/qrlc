/* xmssf.c - XMSS Fast */
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "hash.h"
#include "log.h"
#include "utils.h"
#include "include/types.h"

#include "xmss-alt/algsxmss_fast.h"
#include "xmss-alt/xmss_params.h"

/* prefer to retrieve rand bytes from /dev/random instead from openssl
 * when in a unix system
 */
#ifndef __unix__
#  include <openssl/rand.h>
#endif

#define QRL_XMSS_SEED_SIZE 48
#define QRL_ADDR_DESC_SIZE 3

#define STRING_OK "ok"

#define GET_SIG(x) ((x >> 20) & 0x0f)
#define GET_HF(x) ((x >> 16) & 0x0f)
#define GET_AF(x) ((x >> 12) & 0x0f)
#define GET_P1(x) ((x >> 8) & 0x0f)

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
int qrl_gen_keypair(int addr_desc) {
  int ret = 0;

  /* SIG TYPE 0 (XMSS) */
  if (GET_SIG(addr_desc) == 0) {
    /* HF type */
    eHashFunction addr_hf;
    switch (GET_HF(addr_desc)) {
      case SHA2_256:
        addr_hf = SHA2_256;
        break;
      case SHAKE_128:
        addr_hf = SHAKE_128;
        break;
      case SHAKE_256:
        addr_hf = SHAKE_256;
        break;
      default:
        QRL_LOG_EX(QRL_LOG_ERROR, "unknown address hash function %d\n",
                   GET_HF(addr_desc));
        return 1;
    }

    /* AF type */
    int addr_fmt;
    switch (GET_AF(addr_desc)) {
      case 0:
        addr_fmt = 0;
        break;
      default:
        QRL_LOG_EX(QRL_LOG_ERROR, "unknown address format %d\n",
                   GET_AF(addr_desc));
        return 1;
    }
    /* The 4-bits parameter P1, is the height when SIG=0 (XMSS) */
    qu32 height = GET_P1(addr_desc) * 2;

    const qu32 k = 2;
    const qu32 w = 16;
    const qu32 n = 32;

    if (k >= height || (height - k) % 2) {
      QRL_LOG_EX(QRL_LOG_ERROR, "->1\n");
      return 1;
    }

    /* TODO: secure alloc */
    uint8_t seed[QRL_XMSS_SEED_SIZE];

/* If we're in a unix system, retrieve crytographically secure
 * bytes from /dev/random
 */
#ifdef __unix__
    do {
      /* fdr - file descriptor random */
      int fdr = open("/dev/random", O_RDONLY);
      if (fdr < 0) {
        QRL_LOG_EX(QRL_LOG_ERROR, "couldn't open /dev/random\n");
        return 1;
      }

      int len = 0;
      QRL_LOG("generating random bytes...");
      while (len != QRL_XMSS_SEED_SIZE) {
        /* wait for some time to replenish the ring */
        //sleep(1);
        len += read(fdr, seed + len, QRL_XMSS_SEED_SIZE - len);
      }
      puts(STRING_OK);
      //      if ((len = read(fdr, seed, QRL_XMSS_SEED_SIZE)) <
      //      QRL_XMSS_SEED_SIZE) {
      //        QRL_LOG_EX(QRL_LOG_ERROR,
      //                   "FAILED TO READ random bytes from /dev/random. only
      //                   %d " "bytes read. Move the mouse. press some random
      //                   keys, open " "some disk, and try again in a
      //                   minute\n", len);
      //        close(fdr);
      //        return 1;
      //      }
      close(fdr);
    } while (0);
#else
    if (RAND_bytes(seed, QRL_XMSS_SEED_SIZE)) {
      QRL_LOG_EX(QRL_LOG_ERROR, "FAILED TO GENERATE random bytes\n");
      return 1;
    }
#endif
    printf("hexseed: ");
    do {
      /* desc + seed */
      uint8_t desc_seed[QRL_XMSS_SEED_SIZE + 3] = {0};
      desc_seed[0] = (addr_desc >> 16) & 0xff;
      desc_seed[1] = (addr_desc >> 8) & 0xff;
      desc_seed[2] = (addr_desc >> 0) & 0xff;
      memcpy(desc_seed + 3, seed, QRL_XMSS_SEED_SIZE);
      qrl_printx(desc_seed, QRL_XMSS_SEED_SIZE + 3);
    } while (0);

    /* FIXME: secure alloc */
    uint8_t sk[132] = {0};
    uint8_t pk[64] = {0};

    xmss_params params;
    xmss_set_params(&params, n, height, w, k);

    uint32_t stackoffset = 0;
    uint8_t *stack = calloc(1, (height + 1) * n);
    uint8_t *stacklevels = calloc(1, height + 1);
    uint8_t *auth = calloc(1, height * n);
    uint8_t *keep = calloc(1, (height >> 1) * n);
    treehash_inst *treehash = calloc(sizeof(treehash_inst), (height - k));
    uint8_t *th_nodes = calloc(1, (height - k) * n);
    uint8_t *retain = calloc(1, (((1 << k) - k - 1) * n));

    for (qu32 i = 0; i < height - k; i++) {
      treehash[i].node = &th_nodes[n * i];
    }

    /*---------------------.
    |  KEYPAIR GENERATION  |
    `---------------------*/
    bds_state state;
    xmss_set_bds_state(&state, stack, stackoffset, stacklevels, auth, keep,
                       treehash, retain, 0);

    QRL_LOG("generating key pair. may take minutes...");
    if (xmssfast_Genkeypair(addr_hf, &params, pk, sk, &state, seed)) {
      ret = 1;
      goto clean_xmss;
    }
    puts(STRING_OK);

    QRL_LOG("PK hexdump\n");
    qrl_dump(pk, 64);

    /* desc + pk = desc_pk = ePK */
    uint8_t desc_pk[67] = {0};
    desc_pk[0] = (addr_desc >> 16) & 0xff;
    desc_pk[1] = (addr_desc >> 8) & 0xff;
    desc_pk[2] = (addr_desc >> 0) & 0xff;
    memcpy(desc_pk + 3, pk, 64);

    uint8_t desc_pk_hash[32] = {0};
    qrl_sha256(desc_pk_hash, desc_pk, 67);

    QRL_LOG("qrl address hexdump SHA256(DESC+PK)\n");
    qrl_dump(desc_pk_hash, 32);

    QRL_LOG("sk hexdump\n");
    qrl_dump(sk, 132);

    /* desc + desc_pk_hash */
    uint8_t verh[35] = {0};
    verh[0] = (addr_desc >> 16) & 0xff;
    verh[1] = (addr_desc >> 8) & 0xff;
    verh[2] = (addr_desc >> 0) & 0xff;
    memcpy(verh + 3, desc_pk_hash, 32);

    uint8_t verh_hash[32] = {0};
    qrl_sha256(verh_hash, verh, 35);

    QRL_LOG("QRL address ");

    /* The actual QRL address format  */
    uint8_t qrl_addr[40] = {0};
    qrl_addr[0] = (addr_desc >> 16) & 0xff;
    qrl_addr[1] = (addr_desc >> 8) & 0xff;
    qrl_addr[2] = (addr_desc >> 0) & 0xff;
    memcpy(qrl_addr + 3, desc_pk_hash, 32);
    memcpy(qrl_addr + 3 + 32, verh_hash + 32 - 4, 4);
    printf("Q");
    qrl_printx(qrl_addr, 39);

  clean_xmss:
    free(stack);
    free(stacklevels);
    free(auth);
    free(keep);
    free(treehash);
    free(th_nodes);
    free(retain);
  } else if (GET_SIG(addr_desc) == 1) {
    /* multi sig */
    QRL_LOG_EX(QRL_LOG_ERROR, "unknowm signature type %d\n",
               GET_SIG(addr_desc));
    assert(0);
    return 1;
  } else {
    QRL_LOG_EX(QRL_LOG_ERROR, "unknowm signature type %d\n",
               GET_SIG(addr_desc));
    assert(0);
    return 1;
  }

  return ret;
}
// int xmss_Verifysig(eHashFunction hash_func,
//                    wots_params *wotsParams,
//                    unsigned char *msg,
//                    size_t msglen,
//                    unsigned char *sig_msg,
//                    const unsigned char *pk,
//                    unsigned char h);

/* So you and I won't have to scroll up and down */
/* QRL address descriptor layout DESC (24 bits). */
/*------------------------------------------------.
|  4 bits |  4 bits  | 4 bits |  4 bits  | 8 bits |
|    SIG  |     HF   |   AF   |    P1    |   P2   |
`------------------------------------------------*/
/* 23 bit <-------------------------------- 0 bit */
int qrl_verify_sig(qvec_t epkey, qvec_t msg, qvec_t sig) {
  if (epkey.len != 64 + QRL_ADDR_DESC_SIZE) {
    QRL_LOG_EX(QRL_LOG_ERROR, "invalid epkey length: %d\n", epkey.len);
    return 1;
  }
  if (GET_SIGB(epkey.data[0]) == 0) {
    assert(msg.len >= 32);
    xmss_params xparams;
    const int k = 2;
    const int w = 16;
    const int n = 32;
    uint8_t height = GET_P1B(epkey.data[1]) * 2;

    uint8_t output_msg[32] = {0};
    memcpy(output_msg, msg.data, msg.len);

    xmss_set_params(&xparams, n, height, w, k);

    return xmss_Verifysig(GET_HFB(epkey.data[0]), &(xparams.wots_par), output_msg,
                          32, sig.data,
                          /* skip 3 bytes of the epkey */
                          epkey.data + QRL_ADDR_DESC_SIZE, height);
  } else {
    QRL_LOG_EX(QRL_LOG_ERROR, "unsupported sig type: %d\n", GET_SIGB(epkey.data[0]));
    return 1;
  }

  return 1;
}
