#ifndef QXMSS_H
#define QXMSS_H
#include "include/types.h"

extern qvec_t xmss_gen_pubkey(qvec_t hexseed);
extern int xmss_verify_sig(
                   qvec_t msg,
                   qvec_t sig,
                   qvec_t pub_key);
extern qvec_t xmss_pubkey_to_pubaddr(qvec_t pubkey);


#endif
