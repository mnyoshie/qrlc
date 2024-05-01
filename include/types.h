#ifndef QRL_TYPES_H
#define QRL_TYPES_H

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
//  size_t header_hash_len;
//  qu8 *header_hash;
  qvec_t hash_hdr;
  qu64 block_number;

  // unix since epoch jan 1, 1970
  qu64 timestamp; 

//  size_t pheader_hash_len;
//  qu8 *pheader_hash;
  qvec_t hash_phdr;

  qu64 reward_block;
  qu64 reward_fee;

  qvec_t merkle_root;
//  size_t merkle_root_len;
//  qu8 *merkle_root;

  qu64 mining_nonce;
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
  qu32 n_amounts; 
  qu32 *amounts; 
  qu32 n_addrs_to; 
  qvec_t *addrs_to; 
};

typedef struct qtx_coinbase_t qtx_coinbase_t;
struct qtx_coinbase_t { 
  qu32 amount; 
  qvec_t addr_to; 
};


typedef struct qtx_t qtx_t;
struct qtx_t { 
  qtx_type_t tx_type;

  qvec_t master_addr;
  qvec_t signature;
  qvec_t public_key;

  qvec_t transaction_hash;
  qu32 fee;
  qu32 nonce;
  union {
    qtx_transfer_t transfer;
    qtx_coinbase_t coinbase;
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
extern void free_qblock(qblock_t *qblock);
extern void print_qblock(qblock_t *qblock);

#endif
