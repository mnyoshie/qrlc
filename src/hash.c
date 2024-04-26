#include "hash.h"

/*------------\
 * SHAKE-128  |
 *-----------*/
void qrl_shake128(qvec_t digest, qvec_t msg) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  assert(mdctx != NULL);
  if (EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  if (EVP_DigestUpdate(mdctx, msg.data, msg.len) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  if (EVP_DigestFinalXOF(mdctx, digest.data, digest.len) != 1) {
    EVP_MD_CTX_free(mdctx);
    abort();
  }

  EVP_MD_CTX_free(mdctx);
}

/*------------\
 * SHAKE-256  |
 *-----------*/
//void qrl_shake256(uint8_t *message, int message_len, uint8_t *digest,
//                  int digest_len) {
void qrl_shake256(qvec_t digest, qvec_t message) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  assert(mdctx != NULL);
  if (EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL) != 1) {
    assert(0);
  }

  if (EVP_DigestUpdate(mdctx, message.data, message.len) != 1) {
    assert(0);
  }

  if (EVP_DigestFinalXOF(mdctx, digest.data, digest.len) != 1) {
    assert(0);
  }

  EVP_MD_CTX_free(mdctx);
}

/*------------\
 *  SHA-256   |
 *-----------*/
void qrl_sha256(const void *message, int message_len, uint8_t *digest) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  assert(mdctx != NULL);
  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
    assert(0);
  }

  if (EVP_DigestUpdate(mdctx, message, message_len) != 1) {
    assert(0);
  }

  unsigned int len;
  if (EVP_DigestFinal_ex(mdctx, digest, &len) != 1) {
    assert(0);
  }
  /* paranoid */
  assert(len == 32);

  EVP_MD_CTX_free(mdctx);
}
