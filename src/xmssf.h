#ifndef QXMSSF_H
#define QXMSSF_H
#include "include/types.h"

/* QRL address descriptor layout DESC (24 bits). */
/*------------------------------------------------.
|  4 bits |  4 bits  | 4 bits |  4 bits  | 8 bits |
|    SIG  |     HF   |   AF   |    P1    |   P2   |
`------------------------------------------------*/
/* 23 bit <-------------------------------- 0 bit */
int qrl_gen_keypair(int addr_desc);
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
#endif
