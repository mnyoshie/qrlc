#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "log.h"
#include "xmssf.h"


//#define QDESC_SIG_XMSS     (0 << 20)
//
//#define QDESC_HF_SHA256    (0 << 16)
//#define QDESC_HF_SHAKE128  (1 << 16)
//#define QDESC_HF_SHAKE256  (2 << 16)
//
//#define QDESC_AF_SHA256_2X (0 << 8)
//
//#define QDESC_SET_P1(x)  ((x&0x0f) << 4)
//#define QDESC_SET_P2(x)  ((x&0x0f) << 0)

int main() {
  qrl_log_level = ~0 & ~QRL_LOG_TRACE;
  qrl_gen_keypair(
      QDESC_SIG_XMSS |
      QDESC_HF_SHA256 |
      QDESC_AF_SHA256_2X |
      QDESC_SET_P1(4) |
      QDESC_SET_P2(0)
  );
  qrl_gen_keypair(
      QDESC_SIG_XMSS |
      QDESC_HF_SHAKE128 |
      QDESC_AF_SHA256_2X |
      QDESC_SET_P1(4) |
      QDESC_SET_P2(0)
  );
  qrl_gen_keypair(
      QDESC_SIG_XMSS |
      QDESC_HF_SHAKE256 |
      QDESC_AF_SHA256_2X |
      QDESC_SET_P1(4) |
      QDESC_SET_P2(0)
  );

  qrl_gen_keypair(
      QDESC_SIG_XMSS |
      QDESC_HF_SHA256 |
      QDESC_AF_SHA256_2X |
      QDESC_SET_P1(7) |
      QDESC_SET_P2(0)
  );
  qrl_gen_keypair(
      QDESC_SIG_XMSS |
      QDESC_HF_SHAKE128 |
      QDESC_AF_SHA256_2X |
      QDESC_SET_P1(7) |
      QDESC_SET_P2(0)
  );
  qrl_gen_keypair(
      QDESC_SIG_XMSS |
      QDESC_HF_SHAKE256 |
      QDESC_AF_SHA256_2X |
      QDESC_SET_P1(7) |
      QDESC_SET_P2(0)
  );

  qrl_gen_keypair(
      QDESC_SIG_XMSS |
      QDESC_HF_SHAKE256 |
      QDESC_AF_SHA256_2X |
      QDESC_SET_P1(15) |
      QDESC_SET_P2(0)
  );

  return 0;
}
