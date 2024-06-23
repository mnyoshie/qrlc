#include <stdio.h>
#include "include/types.h"
#include "log.h"
#include "xmss/xmss.h"

/* seed constant */
const int8_t seed_c[] = {0x00, 0x04, 0x00, 0x91, 0xa2, 0x44, 0x64, 0x5d, 0x1c,
                         0x16, 0xda, 0x90, 0xe9, 0x36, 0x3e, 0x71, 0xf8, 0x42,
                         0x04, 0x8f, 0xfa, 0x9b, 0xf6, 0x9a, 0x8b, 0x1a, 0xea,
                         0xe3, 0x6f, 0x6d, 0xcd, 0xa8, 0xab, 0xfa, 0x8e, 0xc3,
                         0x1e, 0x3a, 0xd5, 0xee, 0x7e, 0xe6, 0xe3, 0x8a, 0xf7,
                         0xae, 0x95, 0xd4, 0xcc, 0x41, 0x36};

qvec_t seed = {.data = (void *)seed_c, .len = 51};
qvec_t msg =
    (qvec_t){.data = (void *)"shikanoko nokonoko koshitantan.", .len = 32};

#define NB_OTS 256


#define EXPECT_TRUE(a) do {if (!(a)) return 1;} while (0)
#define EXPECT_FALSE(a) do {if (a) return 1;} while (0)
#define EXPECT_NE(a, b) do {if (!((a)!=(b))) return 1;} while (0)
#define EXPECT_GT(a, b) do {if (!((a)>(b))) return 1;} while (0)
#define EXPECT_EQ(a, b) do {if ((a)!=(b)) return 1;} while (0)

#define ASSERT_NE(a, b) do {if (!((a)!=(b))) return 2;} while (0)
#define ASSERT_GT(a, b) do {if (!((a)>(b))) return 2;} while (0)
#define ASSERT_EQ(a, b) do {if ((a)!=(b)) return 2;} while (0)

#define SKIP_TRUE(a) do {if ((a)) return 3;} while (0)
#define SKIP_FALSE(a) do {if (!(a)) return 3;} while (0)
#define SKIP_NE(a, b) do {if (((a)!=(b))) return 3;} while (0)
#define SKIP_EQ(a, b) do {if (((a)==(b))) return 3;} while (0)
#define SKIP_GT(a, b) do {if (((a)>(b))) return 3;} while (0)

typedef struct xmss xmss;
struct xmss {
  xmss_tree_t *tree;
  qvec_t pub_key, *sig;
};

int test_setup(xmss *fixture) {
  fixture->tree = xmss_gen_tree(seed);
  ASSERT_NE(fixture->tree, NULL);
  fixture->pub_key = xmss_tree_pubkey(fixture->tree);
  ASSERT_NE(fixture->pub_key.data, NULL);
  fixture->sig = calloc(sizeof(qvec_t), NB_OTS);
  ASSERT_NE(fixture->sig, NULL);
  return 0;
}

int test_teardown(xmss *fixture) {
  xmss_tree_free(fixture->tree);
  qrl_qvecfree(fixture->pub_key);
  for (int i = 0; i < NB_OTS; i++) qrl_qvecfree(fixture->sig[i]);
  free(fixture->sig);
  return 0;
}

int sign_msg(xmss *fixture, uint32_t ots) {
  fixture->sig[ots] = xmss_tree_sign_msg(fixture->tree, msg, ots);
  EXPECT_TRUE(fixture->sig[ots].data != NULL);
  EXPECT_TRUE(fixture->sig[ots].len > (size_t)1024);
  return 0;
}

int verify_msg(xmss *fixture, uint32_t ots) {
  qvec_t sig = fixture->sig[ots];
  SKIP_TRUE(sig.data == NULL);
  SKIP_TRUE(sig.len < (size_t)1024);
  EXPECT_FALSE(xmss_verify_sig(msg, sig, fixture->pub_key));
  sig.data[32] = ~sig.data[32];
  EXPECT_TRUE(xmss_verify_sig(msg, sig, fixture->pub_key));
  return 0;
}

int main() {
  size_t passed = 0, failed = 0, skipped = 0;
  qrl_log_level = ~0 & ~QLOG_TRACE;
  if (xmss_secure_heap_init() != 1) {
    fprintf(stderr, "failed to secure heap\n");
    abort();
  }
  xmss fixture = {0};

#define HANDLE_STATE(x, inc) {\
  int ret2 = x; \
  printf(" ...... "); \
  switch(ret2) { \
    case 0: printf("OK\n");  break; \
    case 1: case 2: printf("FAILED\n");  break; \
    case 3: printf("SKIPPED\n");  break; \
  } \
  switch (ret2) { \
    case 0: if (inc) passed++; break;\
    case 1: if (inc) failed++; break; \
    case 2: if (inc) failed++; goto exit;\
    case 3: if (inc) skipped++; break;\
  } \
}

#define HANDLE_RET(s, x, ...) {\
  printf(s " " #x);  \
  printf(__VA_ARGS__); \
  fflush(stdout); \
  int ret = x; \
  HANDLE_STATE(ret, 1); \
}

  do
  HANDLE_RET("[ SETUP    ]", test_setup(&fixture), "")
  while (0);

  for (int i = 0; i < NB_OTS; i++) {
    HANDLE_RET("[ RUN      ]", sign_msg(&fixture, i), " ots %d ", i);
    HANDLE_RET("[ RUN      ]", verify_msg(&fixture, i), " ots %d ", i);
  }
exit:
  (void)test_teardown(&fixture);
  xmss_secure_heap_release();
  printf("[==========]\n%s\n", failed ? 
         "[  FAILED  ]":
         "[  PASSED  ]");
  printf("passed %zu\n", passed);
  printf("failed %zu\n", failed);
  printf("skipped %zu\n", skipped);
  return failed?1:0;
}
