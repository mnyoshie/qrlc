#ifndef QHASH_H
#define QHASH_H

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <assert.h>

#include "include/types.h"

/*------------\
 * SHAKE-128  |
 *-----------*/
extern void qrl_shake128(qvec_t digest, qvec_t msg);

/*------------\
 * SHAKE-256  |
 *-----------*/
extern void qrl_shake256(qvec_t digest, qvec_t message);

/*------------\
 *  SHA-256   |
 *-----------*/
extern void qrl_sha256(const void *message, int message_len, uint8_t *digest);

#endif /* QHASH_H */
