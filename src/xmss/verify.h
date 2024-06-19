#ifndef QXMSS_VERIFY_H
#define QXMSS_VERIFY_H
/* xmss.c and xmss.h works independent of libqrlc */

#if defined(LIBQRLC)
#define XMSS_VEC qvec_t
#else
#define XMSS_VEC vec_t

/* Never modify this struct. It must be the same as
 * qvec_t and don't mess with those either.
 */
typedef struct vec_t vec_t;
struct vec_t {
  size_t len;
  char *data;
};
#endif


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
                   XMSS_VEC msg,
                   XMSS_VEC sig,
                   XMSS_VEC pub_key);
#undef XMSS_VEC

#endif
