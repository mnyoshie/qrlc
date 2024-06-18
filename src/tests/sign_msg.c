#include "include/types.h"
#include "log.h"
#include "utest.h"
#include "xmss.h"

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

struct xmss {
  xmss_tree_t *tree;
  qvec_t pub_key;
};

UTEST_F_SETUP(xmss) {
  utest_fixture->tree = xmss_gen_tree(seed);
  ASSERT_NE(utest_fixture->tree, NULL);
  utest_fixture->pub_key = xmss_tree_pubkey(utest_fixture->tree);
}

UTEST_F_TEARDOWN(xmss) {
  ASSERT_NE(utest_fixture->tree, NULL);
  xmss_tree_free(utest_fixture->tree);
  qrl_qvecfree(utest_fixture->pub_key);
}

#define DEFINE_TEST_F_OTS(n)                                         \
  UTEST_F(xmss, OTS_##n) {                                           \
    qvec_t sig = xmss_tree_sign_msg(utest_fixture->tree, msg, n);    \
    ASSERT_NE(sig.data, NULL);                                       \
    ASSERT_GT(sig.len, (size_t)64);                                  \
    EXPECT_FALSE(xmss_verify_sig(msg, sig, utest_fixture->pub_key)); \
    sig.data[32] = ~sig.data[32];                                    \
    EXPECT_TRUE(xmss_verify_sig(msg, sig, utest_fixture->pub_key));  \
    sig.data[32] = ~sig.data[32];                                    \
    EXPECT_FALSE(xmss_verify_sig(msg, sig, utest_fixture->pub_key)); \
    qrl_qvecfree(sig);                                               \
  }

#define DEFINE_TEST_OTS(n)                            \
  UTEST(xmsss, OTS_##n) {                             \
    qvec_t pub_key = xmss_gen_pubkey(seed);           \
    ASSERT_NE(pub_key.data, NULL);                    \
    qvec_t sig = xmss_sign_msg(seed, msg, n);         \
    ASSERT_NE(sig.data, NULL);                        \
    ASSERT_GT(sig.len, (size_t)64);                   \
    EXPECT_FALSE(xmss_verify_sig(msg, sig, pub_key)); \
    sig.data[32] = ~sig.data[32];                     \
    EXPECT_TRUE(xmss_verify_sig(msg, sig, pub_key));  \
    qrl_qvecfree(sig);                                \
    qrl_qvecfree(pub_key);                            \
  }

DEFINE_TEST_F_OTS(0);
DEFINE_TEST_F_OTS(1);
DEFINE_TEST_F_OTS(32);
DEFINE_TEST_F_OTS(37);
DEFINE_TEST_F_OTS(42);
DEFINE_TEST_F_OTS(64);
DEFINE_TEST_F_OTS(128);
DEFINE_TEST_F_OTS(137);
DEFINE_TEST_F_OTS(255);

DEFINE_TEST_OTS(0);
DEFINE_TEST_OTS(64);
DEFINE_TEST_OTS(128);
DEFINE_TEST_OTS(255);

UTEST_STATE();

int main(int argc, char *argv[]) {
  qrl_log_level = ~0 & ~QLOG_TRACE;
  if (xmss_secure_heap_init() != 1) {
    fprintf(stderr, "failed to secure heap\n");
    abort();
  }
  int ret = utest_main(argc, argv);
  xmss_secure_heap_release();
  return ret;
}
