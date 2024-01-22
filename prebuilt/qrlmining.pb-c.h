/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: qrlmining.proto (4.0.3) */

#ifndef PROTOBUF_C_qrlmining_2eproto__INCLUDED
#define PROTOBUF_C_qrlmining_2eproto__INCLUDED

#include "include/protobuf-c.h"

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "include/qrl.pb-c.h"

typedef struct Qrl__GetBlockMiningCompatibleReq Qrl__GetBlockMiningCompatibleReq;
typedef struct Qrl__GetLastBlockHeaderReq Qrl__GetLastBlockHeaderReq;
typedef struct Qrl__GetBlockMiningCompatibleResp Qrl__GetBlockMiningCompatibleResp;
typedef struct Qrl__GetLastBlockHeaderResp Qrl__GetLastBlockHeaderResp;
typedef struct Qrl__GetBlockToMineReq Qrl__GetBlockToMineReq;
typedef struct Qrl__GetBlockToMineResp Qrl__GetBlockToMineResp;
typedef struct Qrl__SubmitMinedBlockReq Qrl__SubmitMinedBlockReq;
typedef struct Qrl__SubmitMinedBlockResp Qrl__SubmitMinedBlockResp;


/* --- enums --- */


/* --- messages --- */

struct  Qrl__GetBlockMiningCompatibleReq
{
  ProtobufCMessage base;
  /*
   * Used for getlastblockheader and getblockheaderbyheight
   */
  /*
   * if height = 0, this means getlastblockheader
   */
  uint64_t height;
};
#define QRL__GET_BLOCK_MINING_COMPATIBLE_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&qrl__get_block_mining_compatible_req__descriptor) \
, 0 }


struct  Qrl__GetLastBlockHeaderReq
{
  ProtobufCMessage base;
  uint64_t height;
};
#define QRL__GET_LAST_BLOCK_HEADER_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&qrl__get_last_block_header_req__descriptor) \
, 0 }


struct  Qrl__GetBlockMiningCompatibleResp
{
  ProtobufCMessage base;
  Qrl__BlockHeader *blockheader;
  Qrl__BlockMetaData *blockmetadata;
};
#define QRL__GET_BLOCK_MINING_COMPATIBLE_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&qrl__get_block_mining_compatible_resp__descriptor) \
, NULL, NULL }


struct  Qrl__GetLastBlockHeaderResp
{
  ProtobufCMessage base;
  uint64_t difficulty;
  uint64_t height;
  uint64_t timestamp;
  uint64_t reward;
  char *hash;
  uint64_t depth;
};
#define QRL__GET_LAST_BLOCK_HEADER_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&qrl__get_last_block_header_resp__descriptor) \
, 0, 0, 0, 0, (char *)protobuf_c_empty_string, 0 }


struct  Qrl__GetBlockToMineReq
{
  ProtobufCMessage base;
  ProtobufCBinaryData wallet_address;
};
#define QRL__GET_BLOCK_TO_MINE_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&qrl__get_block_to_mine_req__descriptor) \
, {0,NULL} }


struct  Qrl__GetBlockToMineResp
{
  ProtobufCMessage base;
  /*
   * max length 112 bytes, otherwise xmr-stak will hiccup
   */
  char *blocktemplate_blob;
  /*
   * difficulty that the new block should meet
   */
  uint64_t difficulty;
  uint64_t height;
  uint32_t reserved_offset;
  char *seed_hash;
};
#define QRL__GET_BLOCK_TO_MINE_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&qrl__get_block_to_mine_resp__descriptor) \
, (char *)protobuf_c_empty_string, 0, 0, 0, (char *)protobuf_c_empty_string }


struct  Qrl__SubmitMinedBlockReq
{
  ProtobufCMessage base;
  /*
   * blocktemplate_blob with the correct nonce
   */
  ProtobufCBinaryData blob;
};
#define QRL__SUBMIT_MINED_BLOCK_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&qrl__submit_mined_block_req__descriptor) \
, {0,NULL} }


struct  Qrl__SubmitMinedBlockResp
{
  ProtobufCMessage base;
  /*
   * It seems there are no special fields for success/error reporting, does gRPC automatically give me something?
   */
  protobuf_c_boolean error;
};
#define QRL__SUBMIT_MINED_BLOCK_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&qrl__submit_mined_block_resp__descriptor) \
, 0 }


/* Qrl__GetBlockMiningCompatibleReq methods */
void   qrl__get_block_mining_compatible_req__init
                     (Qrl__GetBlockMiningCompatibleReq         *message);
size_t qrl__get_block_mining_compatible_req__get_packed_size
                     (const Qrl__GetBlockMiningCompatibleReq   *message);
size_t qrl__get_block_mining_compatible_req__pack
                     (const Qrl__GetBlockMiningCompatibleReq   *message,
                      uint8_t             *out);
size_t qrl__get_block_mining_compatible_req__pack_to_buffer
                     (const Qrl__GetBlockMiningCompatibleReq   *message,
                      ProtobufCBuffer     *buffer);
Qrl__GetBlockMiningCompatibleReq *
       qrl__get_block_mining_compatible_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   qrl__get_block_mining_compatible_req__free_unpacked
                     (Qrl__GetBlockMiningCompatibleReq *message,
                      ProtobufCAllocator *allocator);
/* Qrl__GetLastBlockHeaderReq methods */
void   qrl__get_last_block_header_req__init
                     (Qrl__GetLastBlockHeaderReq         *message);
size_t qrl__get_last_block_header_req__get_packed_size
                     (const Qrl__GetLastBlockHeaderReq   *message);
size_t qrl__get_last_block_header_req__pack
                     (const Qrl__GetLastBlockHeaderReq   *message,
                      uint8_t             *out);
size_t qrl__get_last_block_header_req__pack_to_buffer
                     (const Qrl__GetLastBlockHeaderReq   *message,
                      ProtobufCBuffer     *buffer);
Qrl__GetLastBlockHeaderReq *
       qrl__get_last_block_header_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   qrl__get_last_block_header_req__free_unpacked
                     (Qrl__GetLastBlockHeaderReq *message,
                      ProtobufCAllocator *allocator);
/* Qrl__GetBlockMiningCompatibleResp methods */
void   qrl__get_block_mining_compatible_resp__init
                     (Qrl__GetBlockMiningCompatibleResp         *message);
size_t qrl__get_block_mining_compatible_resp__get_packed_size
                     (const Qrl__GetBlockMiningCompatibleResp   *message);
size_t qrl__get_block_mining_compatible_resp__pack
                     (const Qrl__GetBlockMiningCompatibleResp   *message,
                      uint8_t             *out);
size_t qrl__get_block_mining_compatible_resp__pack_to_buffer
                     (const Qrl__GetBlockMiningCompatibleResp   *message,
                      ProtobufCBuffer     *buffer);
Qrl__GetBlockMiningCompatibleResp *
       qrl__get_block_mining_compatible_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   qrl__get_block_mining_compatible_resp__free_unpacked
                     (Qrl__GetBlockMiningCompatibleResp *message,
                      ProtobufCAllocator *allocator);
/* Qrl__GetLastBlockHeaderResp methods */
void   qrl__get_last_block_header_resp__init
                     (Qrl__GetLastBlockHeaderResp         *message);
size_t qrl__get_last_block_header_resp__get_packed_size
                     (const Qrl__GetLastBlockHeaderResp   *message);
size_t qrl__get_last_block_header_resp__pack
                     (const Qrl__GetLastBlockHeaderResp   *message,
                      uint8_t             *out);
size_t qrl__get_last_block_header_resp__pack_to_buffer
                     (const Qrl__GetLastBlockHeaderResp   *message,
                      ProtobufCBuffer     *buffer);
Qrl__GetLastBlockHeaderResp *
       qrl__get_last_block_header_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   qrl__get_last_block_header_resp__free_unpacked
                     (Qrl__GetLastBlockHeaderResp *message,
                      ProtobufCAllocator *allocator);
/* Qrl__GetBlockToMineReq methods */
void   qrl__get_block_to_mine_req__init
                     (Qrl__GetBlockToMineReq         *message);
size_t qrl__get_block_to_mine_req__get_packed_size
                     (const Qrl__GetBlockToMineReq   *message);
size_t qrl__get_block_to_mine_req__pack
                     (const Qrl__GetBlockToMineReq   *message,
                      uint8_t             *out);
size_t qrl__get_block_to_mine_req__pack_to_buffer
                     (const Qrl__GetBlockToMineReq   *message,
                      ProtobufCBuffer     *buffer);
Qrl__GetBlockToMineReq *
       qrl__get_block_to_mine_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   qrl__get_block_to_mine_req__free_unpacked
                     (Qrl__GetBlockToMineReq *message,
                      ProtobufCAllocator *allocator);
/* Qrl__GetBlockToMineResp methods */
void   qrl__get_block_to_mine_resp__init
                     (Qrl__GetBlockToMineResp         *message);
size_t qrl__get_block_to_mine_resp__get_packed_size
                     (const Qrl__GetBlockToMineResp   *message);
size_t qrl__get_block_to_mine_resp__pack
                     (const Qrl__GetBlockToMineResp   *message,
                      uint8_t             *out);
size_t qrl__get_block_to_mine_resp__pack_to_buffer
                     (const Qrl__GetBlockToMineResp   *message,
                      ProtobufCBuffer     *buffer);
Qrl__GetBlockToMineResp *
       qrl__get_block_to_mine_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   qrl__get_block_to_mine_resp__free_unpacked
                     (Qrl__GetBlockToMineResp *message,
                      ProtobufCAllocator *allocator);
/* Qrl__SubmitMinedBlockReq methods */
void   qrl__submit_mined_block_req__init
                     (Qrl__SubmitMinedBlockReq         *message);
size_t qrl__submit_mined_block_req__get_packed_size
                     (const Qrl__SubmitMinedBlockReq   *message);
size_t qrl__submit_mined_block_req__pack
                     (const Qrl__SubmitMinedBlockReq   *message,
                      uint8_t             *out);
size_t qrl__submit_mined_block_req__pack_to_buffer
                     (const Qrl__SubmitMinedBlockReq   *message,
                      ProtobufCBuffer     *buffer);
Qrl__SubmitMinedBlockReq *
       qrl__submit_mined_block_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   qrl__submit_mined_block_req__free_unpacked
                     (Qrl__SubmitMinedBlockReq *message,
                      ProtobufCAllocator *allocator);
/* Qrl__SubmitMinedBlockResp methods */
void   qrl__submit_mined_block_resp__init
                     (Qrl__SubmitMinedBlockResp         *message);
size_t qrl__submit_mined_block_resp__get_packed_size
                     (const Qrl__SubmitMinedBlockResp   *message);
size_t qrl__submit_mined_block_resp__pack
                     (const Qrl__SubmitMinedBlockResp   *message,
                      uint8_t             *out);
size_t qrl__submit_mined_block_resp__pack_to_buffer
                     (const Qrl__SubmitMinedBlockResp   *message,
                      ProtobufCBuffer     *buffer);
Qrl__SubmitMinedBlockResp *
       qrl__submit_mined_block_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   qrl__submit_mined_block_resp__free_unpacked
                     (Qrl__SubmitMinedBlockResp *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Qrl__GetBlockMiningCompatibleReq_Closure)
                 (const Qrl__GetBlockMiningCompatibleReq *message,
                  void *closure_data);
typedef void (*Qrl__GetLastBlockHeaderReq_Closure)
                 (const Qrl__GetLastBlockHeaderReq *message,
                  void *closure_data);
typedef void (*Qrl__GetBlockMiningCompatibleResp_Closure)
                 (const Qrl__GetBlockMiningCompatibleResp *message,
                  void *closure_data);
typedef void (*Qrl__GetLastBlockHeaderResp_Closure)
                 (const Qrl__GetLastBlockHeaderResp *message,
                  void *closure_data);
typedef void (*Qrl__GetBlockToMineReq_Closure)
                 (const Qrl__GetBlockToMineReq *message,
                  void *closure_data);
typedef void (*Qrl__GetBlockToMineResp_Closure)
                 (const Qrl__GetBlockToMineResp *message,
                  void *closure_data);
typedef void (*Qrl__SubmitMinedBlockReq_Closure)
                 (const Qrl__SubmitMinedBlockReq *message,
                  void *closure_data);
typedef void (*Qrl__SubmitMinedBlockResp_Closure)
                 (const Qrl__SubmitMinedBlockResp *message,
                  void *closure_data);

/* --- services --- */

typedef struct Qrl__MiningAPI_Service Qrl__MiningAPI_Service;
struct Qrl__MiningAPI_Service
{
  ProtobufCService base;
  void (*get_block_mining_compatible)(Qrl__MiningAPI_Service *service,
                                      const Qrl__GetBlockMiningCompatibleReq *input,
                                      Qrl__GetBlockMiningCompatibleResp_Closure closure,
                                      void *closure_data);
  void (*get_last_block_header)(Qrl__MiningAPI_Service *service,
                                const Qrl__GetLastBlockHeaderReq *input,
                                Qrl__GetLastBlockHeaderResp_Closure closure,
                                void *closure_data);
  void (*get_block_to_mine)(Qrl__MiningAPI_Service *service,
                            const Qrl__GetBlockToMineReq *input,
                            Qrl__GetBlockToMineResp_Closure closure,
                            void *closure_data);
  void (*submit_mined_block)(Qrl__MiningAPI_Service *service,
                             const Qrl__SubmitMinedBlockReq *input,
                             Qrl__SubmitMinedBlockResp_Closure closure,
                             void *closure_data);
};
typedef void (*Qrl__MiningAPI_ServiceDestroy)(Qrl__MiningAPI_Service *);
void qrl__mining_api__init (Qrl__MiningAPI_Service *service,
                            Qrl__MiningAPI_ServiceDestroy destroy);
#define QRL__MINING_API__BASE_INIT \
    { &qrl__mining_api__descriptor, protobuf_c_service_invoke_internal, NULL }
#define QRL__MINING_API__INIT(function_prefix__) \
    { QRL__MINING_API__BASE_INIT,\
      function_prefix__ ## get_block_mining_compatible,\
      function_prefix__ ## get_last_block_header,\
      function_prefix__ ## get_block_to_mine,\
      function_prefix__ ## submit_mined_block  }
void qrl__mining_api__get_block_mining_compatible(ProtobufCService *service,
                                                  const Qrl__GetBlockMiningCompatibleReq *input,
                                                  Qrl__GetBlockMiningCompatibleResp_Closure closure,
                                                  void *closure_data);
void qrl__mining_api__get_last_block_header(ProtobufCService *service,
                                            const Qrl__GetLastBlockHeaderReq *input,
                                            Qrl__GetLastBlockHeaderResp_Closure closure,
                                            void *closure_data);
void qrl__mining_api__get_block_to_mine(ProtobufCService *service,
                                        const Qrl__GetBlockToMineReq *input,
                                        Qrl__GetBlockToMineResp_Closure closure,
                                        void *closure_data);
void qrl__mining_api__submit_mined_block(ProtobufCService *service,
                                         const Qrl__SubmitMinedBlockReq *input,
                                         Qrl__SubmitMinedBlockResp_Closure closure,
                                         void *closure_data);

/* --- descriptors --- */

extern const ProtobufCMessageDescriptor qrl__get_block_mining_compatible_req__descriptor;
extern const ProtobufCMessageDescriptor qrl__get_last_block_header_req__descriptor;
extern const ProtobufCMessageDescriptor qrl__get_block_mining_compatible_resp__descriptor;
extern const ProtobufCMessageDescriptor qrl__get_last_block_header_resp__descriptor;
extern const ProtobufCMessageDescriptor qrl__get_block_to_mine_req__descriptor;
extern const ProtobufCMessageDescriptor qrl__get_block_to_mine_resp__descriptor;
extern const ProtobufCMessageDescriptor qrl__submit_mined_block_req__descriptor;
extern const ProtobufCMessageDescriptor qrl__submit_mined_block_resp__descriptor;
extern const ProtobufCServiceDescriptor qrl__mining_api__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_qrlmining_2eproto__INCLUDED */
