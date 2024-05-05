#ifndef QRL_DEV_CONFIG_H
#define QRL_DEV_CONFIG_H

#define QRL_MAINNET1 "mainnet-1.automated.theqrl.org:19009"
#define QRL_MAINNET2 "mainnet-2.automated.theqrl.org:19009"

/* self.hard_fork_heights = [942375, 1938000, 2078800] */
#define QRL_HARD_FORK_HEIGHT0 942375
#define QRL_HARD_FORK_HEIGHT1 1938000
#define QRL_HARD_FORK_HEIGHT2 2078800

#define QRL_BANNED_ADDRESS1                                                 \
  (qvec_t) {                                                                \
    .data =                                                                 \
        (qu8[]){0x01, 0x06, 0x00, 0xfc, 0xd0, 0xdb, 0x86, 0x9d, 0x2e, 0x1b, \
                0x17, 0xb4, 0x52, 0xbd, 0xf9, 0x84, 0x8f, 0x6f, 0xe8, 0xc7, \
                0x4e, 0xe5, 0xb8, 0xf9, 0x35, 0x40, 0x8c, 0xc5, 0x58, 0xc6, \
                0x01, 0xfb, 0x69, 0xeb, 0x55, 0x3f, 0xa9, 0x16, 0xa1},      \
    .len = 39                                                               \
  }
#define QRL_BLOCK_MINING_NONCE_OFFSET 39
#define QRL_BLOCK_EXTRA_NONCE_OFFSET 43

#define QRL_TRANSACTION_MULTI_OUTPUT_LIMIT 1000

extern const char *qget_mainnet_address(qu32 i);

/* self.hard_fork_heights = [942375, 1938000, 2078800] */
extern qu64 qget_hardfork_height(qu64 i);
 
extern const qvec_t *qget_banned_address(qu64 i);
#endif
