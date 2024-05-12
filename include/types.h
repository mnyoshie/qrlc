#ifndef QRL_TYPES_H
#define QRL_TYPES_H

#define LIBQRLC

#include <stdlib.h>
#include "qint.h"

#define QVEC_NULL (qvec_t){.data=NULL, .len=0}

typedef struct qvec_t qvec_t;
struct qvec_t {
  size_t len;
  qu8 *data;
};

// internal qrl structure
typedef struct qblock_hdr_t qblock_hdr_t;
struct qblock_hdr_t {
  // assumed to be 32
  qvec_t hash_hdr;
  qu64 block_number;

  // unix since epoch jan 1, 1970
  qu64 timestamp; 

  qvec_t hash_phdr;

  qu64 reward_block;
  qu64 reward_fee;

  qvec_t merkle_root;

  qu32 mining_nonce;
  qu64 extra_nonce;
};

enum qtx_type_t {
  QTX_UNKNOWN = -1,
  QTX_TRANSFER = 7,
  QTX_COINBASE = 8,
  QTX_LATTICEPK = 9,
  QTX_MESSAGE = 10,
  QTX_TOKEN = 11,
  QTX_TRANSFER_TOKEN = 12,
  QTX_SLAVE = 13,

  QTX_MULTISIG_CREATE = 14,
  QTX_MULTISIG_SPEND = 15,
  QTX_MULTISIG_VOTE = 16,

  QTX_PROPOSAL_CREATE = 17,
  QTX_PROPOSAL_VOTE = 18,
};

typedef enum qtx_type_t qtx_type_t;

typedef struct qtx_transfer_t qtx_transfer_t;
struct qtx_transfer_t { 
  qvec_t message_data;
  size_t nb_amounts; 
  qu64 *amounts; 
  size_t nb_addrs_to; 
  qvec_t *addrs_to; 
};

typedef struct qtx_coinbase_t qtx_coinbase_t;
struct qtx_coinbase_t { 
  qu64 amount; 
  qvec_t addr_to; 
};

typedef struct qtx_message_t qtx_message_t;
struct qtx_message_t { 
  qvec_t message_hash; 
  qvec_t addr_to; 
};


typedef struct qtx_transfer_token_t qtx_transfer_token_t;
struct qtx_transfer_token_t { 
  qvec_t token_txhash;
  size_t n_addrs_to;
  qvec_t *addrs_to;
  size_t n_amounts;
  qu64 *amounts;
};

typedef struct qtx_t qtx_t;
struct qtx_t { 
  qtx_type_t tx_type;

  qvec_t master_addr;
  qvec_t signature;
  qvec_t public_key;

  qvec_t tx_hash;
  qu64 fee;
  qu64 nonce;
  union {
    qtx_transfer_t transfer;
    qtx_coinbase_t coinbase;
    qtx_message_t message;
    qtx_transfer_token_t transfer_token;
  };
};

typedef struct qblock_t qblock_t;
struct qblock_t {
  qblock_hdr_t block_hdr;

  size_t nb_txs;
  qtx_t *txs;

  //qgenesis_balance_t genesis_balance;
};

extern qvec_t new_qvec(size_t size);
extern void del_qvec(qvec_t q);
extern void free_qblock(qblock_t *qblock);
extern void print_qblock(qblock_t *qblock, int v);
extern const char *qtx_type2str(qtx_type_t tx_type);
extern qvec_t qrl_qveccpy(const qvec_t a);
extern qvec_t qrl_qveccat(const qvec_t a, const qvec_t b);

#endif
