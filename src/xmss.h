#ifndef QXMSS_H
#define QXMSS_H

/* xmss.c and xmss.h works independent of libqrlc */

#if defined(LIBQRLC)
#define VEC qvec_t
#else
#define VEC vec_t

/* Never modify this struct. It must be the same as
 * qvec_t and don't mess with those either.
 */
typedef struct vec_t vec_t;
struct vec_t {
  size_t len;
  char *data;
};
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
extern VEC xmss_gen_pubkey(VEC hexseed);

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
extern int xmss_verify_sig(
                   VEC msg,
                   VEC sig,
                   VEC pub_key);
extern VEC xmss_pubkey_to_pubaddr(VEC pub_key);
extern VEC xmss_sign_msg(VEC hexseed, VEC msg, uint32_t ots);

#undef VEC

#endif
