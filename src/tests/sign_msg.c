#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "include/types.h"
#include "log.h"
#include "xmss.h"

#ifdef NDEBUG
#error "Dont turn on NO DEBUG!"
#endif

int main() {
  int err = 0;
  qrl_log_level = ~0 & ~QLOG_TRACE;
  uint8_t seed_c1[] = {0x00, 0x04, 0x00, 0x91, 0xa2, 0x44, 0x64, 0x5d, 0x1c,
                       0x16, 0xda, 0x90, 0xe9, 0x36, 0x3e, 0x71, 0xf8, 0x42,
                       0x04, 0x8f, 0xfa, 0x9b, 0xf6, 0x9a, 0x8b, 0x1a, 0xea,
                       0xe3, 0x6f, 0x6d, 0xcd, 0xa8, 0xab, 0xfa, 0x8e, 0xc3,
                       0x1e, 0x3a, 0xd5, 0xee, 0x7e, 0xe6, 0xe3, 0x8a, 0xf7,
                       0xae, 0x95, 0xd4, 0xcc, 0x41, 0x36};



  qvec_t seed1 = {.data = (void*)seed_c1, .len = 51};

  qvec_t pub_key1 = xmss_gen_pubkey(seed1);

  qvec_t msg1 = (qvec_t){.data=(void*)"hello world", .len=12};

#define SET_ERR_IF(x, s)  \
  do {                    \
    if (x) {              \
      fprintf(stderr, s); \
      err = 1;            \
    }                     \
  } while (0)

  qvec_t sig1_0 = xmss_sign_msg(seed1, msg1, 0);
  qvec_t sig1_64 = xmss_sign_msg(seed1, msg1, 64);
  qvec_t sig1_128 = xmss_sign_msg(seed1, msg1, 126);
  qvec_t sig1_255 = xmss_sign_msg(seed1, msg1, 255);

  SET_ERR_IF(xmss_verify_sig(msg1, sig1_0, pub_key1), \
      "ots 0 failed"
  );
  SET_ERR_IF(xmss_verify_sig(msg1, sig1_64, pub_key1), \
      "ots 64 failed"
  );
  SET_ERR_IF(xmss_verify_sig(msg1, sig1_128, pub_key1), \
      "ots 128 failed"
  );
  SET_ERR_IF(xmss_verify_sig(msg1, sig1_255, pub_key1), \
      "ots 255 failed"
  );

  qrl_qvecfree(pub_key1);
  qrl_qvecfree(sig1_0);
  qrl_qvecfree(sig1_64);
  qrl_qvecfree(sig1_128);
  qrl_qvecfree(sig1_255);
  if (err) {
    abort();
  }
  return 0;
}
