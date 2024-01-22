#ifndef QRL_C_H
#define QRL_C_H

#include <stdint.h>

typedef struct qrl_block_header_t qrl_block_header_t;
struct qrl_block_header_t {
  uint8_t header_hash[32];
  uint64_t block_number;
  // unix since epoch jan 1, 1970
  uint64_t timestamp; 
  uint8_t prev_header_hash[32];

  uint64_t block_reward;
  uint64_t fee_reward;

  uint8_t merkle_root[32];

  uint64_t mining_nonce;
  uint64_t extra_nonce;
};

enum qrl_transaction_type_t {
  QRL_TRANSACTION_UNKNOWN = 0,
  QRL_TRANSACTION_TRANSFER = 1,
  QRL_TRANSACTION_COINBASE = 2,
  QRL_TRANSACTION_LATTICEPK = 3,
  QRL_TRANSACTION_MESSAGE = 4,
};
typedef enum qrl_transaction_type_t qrl_transaction_type_t;

typedef struct qrl_transaction_t qrl_transaction_t;
struct qrl_transaction_t {
  
  qrl_transaction_type_t transaction_type;
  uint32_t master_addr_len;
  uint8_t *master_aadr;
  union {
    struct {
      int a; 
    } transfer;
    struct {
      int a;
    } coinbase;

  };
};

typedef struct qrl_block_t qrl_block_t;
struct qrl_block_t {
  qrl_block_header_t block_header;

  size_t nb_transactions;
  qrl_transaction_t *transactions;

  //qrl_genesis_balance_t genesis_balance;

};



#endif /* QRL_C_H */
