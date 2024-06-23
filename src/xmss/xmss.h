#ifndef QXMSS_H
#define QXMSS_H

//#define XMSS_NO_SECURE_HEAP

#include "verify.h"

/* xmss.c and xmss.h works independent of libqrlc */

typedef struct xmss_tree_t xmss_tree_t;
struct xmss_tree_t;
#if defined(LIBQRLC)
#define XMSS_VEC qvec_t
#else
#define XMSS_VEC vec_t
#endif


/* input hexseed format (51 octets):
 *
 *    size          |         name            |       description
 * -----------------+-------------------------+----------------------------
 *  3 octets        |      qrl addr desc      |  QRL  address descriptor
 *  ----------------+-------------------------+----------------------------
 *  48 octets       |         seed            |       random seed
 *  ------------------------------------------+----------------------------
 *
 * output pub_key format (67 octets):
 *
 *    size          |         name            |       description
 * -----------------+-------------------------+----------------------------
 *  3 octets        |      qrl addr desc      |  QRL  address descriptor
 *  ----------------+-------------------------+----------------------------
 *  32 octets       |         root            |       XMSS root
 *  ------------------------------------------+----------------------------
 *  32 octets       |       pub seed          |       public seed
 */
extern XMSS_VEC xmss_gen_pubkey(XMSS_VEC hexseed);

extern XMSS_VEC xmss_pubkey_to_pubaddr(XMSS_VEC pub_key);
extern XMSS_VEC xmss_sign_msg(XMSS_VEC hexseed, XMSS_VEC msg, uint32_t ots);

extern xmss_tree_t *xmss_gen_tree(const XMSS_VEC hexseed);
extern XMSS_VEC xmss_tree_pubkey(const xmss_tree_t *tree);
extern XMSS_VEC xmss_tree_pubaddr(const xmss_tree_t *tree);
extern XMSS_VEC xmss_tree_sign_msg(const xmss_tree_t *tree, XMSS_VEC msg, uint32_t ots);
extern void xmss_tree_free(xmss_tree_t *tree);

extern int xmss_secure_heap_init();
extern int xmss_secure_heap_release();
#undef XMSS_VEC

#endif
