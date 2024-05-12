#ifndef QXMSSF_H
#define QXMSSF_H
#include "include/types.h"

#define QDESC_SIG_XMSS     (0 << 20)

#define QDESC_HF_SHA256    (0 << 16)
#define QDESC_HF_SHAKE128  (1 << 16)
#define QDESC_HF_SHAKE256  (2 << 16)

#define QDESC_AF_SHA256_2X (0 << 12)

#define QDESC_SET_P1(x)  ((x&0x0f) << 8)
#define QDESC_SET_P2(x)  ((x&0x0f) << 0)

/* QRL address descriptor layout DESC (24 bits). */
/*------------------------------------------------.
|  4 bits |  4 bits  | 4 bits |  4 bits  | 8 bits |
|    SIG  |     HF   |   AF   |    P1    |   P2   |
`------------------------------------------------*/
/* 23 bit <-------------------------------- 0 bit */
int __attribute__((deprecated("this has not been rigorously tested. do not use")))  qrl_gen_keypair(int addr_desc);
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
int qrl_verify_sig(qvec_t epkey, qvec_t msg, qvec_t sig);
int qrl_verify_public_address(qvec_t pa, qvec_t pk);
#endif
