/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: qrlmining.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "include/qrlmining.pb-c.h"
void   qrl__get_block_mining_compatible_req__init
                     (Qrl__GetBlockMiningCompatibleReq         *message)
{
  static const Qrl__GetBlockMiningCompatibleReq init_value = QRL__GET_BLOCK_MINING_COMPATIBLE_REQ__INIT;
  *message = init_value;
}
size_t qrl__get_block_mining_compatible_req__get_packed_size
                     (const Qrl__GetBlockMiningCompatibleReq *message)
{
  assert(message->base.descriptor == &qrl__get_block_mining_compatible_req__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t qrl__get_block_mining_compatible_req__pack
                     (const Qrl__GetBlockMiningCompatibleReq *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &qrl__get_block_mining_compatible_req__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t qrl__get_block_mining_compatible_req__pack_to_buffer
                     (const Qrl__GetBlockMiningCompatibleReq *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &qrl__get_block_mining_compatible_req__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Qrl__GetBlockMiningCompatibleReq *
       qrl__get_block_mining_compatible_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Qrl__GetBlockMiningCompatibleReq *)
     protobuf_c_message_unpack (&qrl__get_block_mining_compatible_req__descriptor,
                                allocator, len, data);
}
void   qrl__get_block_mining_compatible_req__free_unpacked
                     (Qrl__GetBlockMiningCompatibleReq *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &qrl__get_block_mining_compatible_req__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   qrl__get_last_block_header_req__init
                     (Qrl__GetLastBlockHeaderReq         *message)
{
  static const Qrl__GetLastBlockHeaderReq init_value = QRL__GET_LAST_BLOCK_HEADER_REQ__INIT;
  *message = init_value;
}
size_t qrl__get_last_block_header_req__get_packed_size
                     (const Qrl__GetLastBlockHeaderReq *message)
{
  assert(message->base.descriptor == &qrl__get_last_block_header_req__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t qrl__get_last_block_header_req__pack
                     (const Qrl__GetLastBlockHeaderReq *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &qrl__get_last_block_header_req__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t qrl__get_last_block_header_req__pack_to_buffer
                     (const Qrl__GetLastBlockHeaderReq *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &qrl__get_last_block_header_req__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Qrl__GetLastBlockHeaderReq *
       qrl__get_last_block_header_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Qrl__GetLastBlockHeaderReq *)
     protobuf_c_message_unpack (&qrl__get_last_block_header_req__descriptor,
                                allocator, len, data);
}
void   qrl__get_last_block_header_req__free_unpacked
                     (Qrl__GetLastBlockHeaderReq *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &qrl__get_last_block_header_req__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   qrl__get_block_mining_compatible_resp__init
                     (Qrl__GetBlockMiningCompatibleResp         *message)
{
  static const Qrl__GetBlockMiningCompatibleResp init_value = QRL__GET_BLOCK_MINING_COMPATIBLE_RESP__INIT;
  *message = init_value;
}
size_t qrl__get_block_mining_compatible_resp__get_packed_size
                     (const Qrl__GetBlockMiningCompatibleResp *message)
{
  assert(message->base.descriptor == &qrl__get_block_mining_compatible_resp__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t qrl__get_block_mining_compatible_resp__pack
                     (const Qrl__GetBlockMiningCompatibleResp *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &qrl__get_block_mining_compatible_resp__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t qrl__get_block_mining_compatible_resp__pack_to_buffer
                     (const Qrl__GetBlockMiningCompatibleResp *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &qrl__get_block_mining_compatible_resp__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Qrl__GetBlockMiningCompatibleResp *
       qrl__get_block_mining_compatible_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Qrl__GetBlockMiningCompatibleResp *)
     protobuf_c_message_unpack (&qrl__get_block_mining_compatible_resp__descriptor,
                                allocator, len, data);
}
void   qrl__get_block_mining_compatible_resp__free_unpacked
                     (Qrl__GetBlockMiningCompatibleResp *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &qrl__get_block_mining_compatible_resp__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   qrl__get_last_block_header_resp__init
                     (Qrl__GetLastBlockHeaderResp         *message)
{
  static const Qrl__GetLastBlockHeaderResp init_value = QRL__GET_LAST_BLOCK_HEADER_RESP__INIT;
  *message = init_value;
}
size_t qrl__get_last_block_header_resp__get_packed_size
                     (const Qrl__GetLastBlockHeaderResp *message)
{
  assert(message->base.descriptor == &qrl__get_last_block_header_resp__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t qrl__get_last_block_header_resp__pack
                     (const Qrl__GetLastBlockHeaderResp *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &qrl__get_last_block_header_resp__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t qrl__get_last_block_header_resp__pack_to_buffer
                     (const Qrl__GetLastBlockHeaderResp *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &qrl__get_last_block_header_resp__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Qrl__GetLastBlockHeaderResp *
       qrl__get_last_block_header_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Qrl__GetLastBlockHeaderResp *)
     protobuf_c_message_unpack (&qrl__get_last_block_header_resp__descriptor,
                                allocator, len, data);
}
void   qrl__get_last_block_header_resp__free_unpacked
                     (Qrl__GetLastBlockHeaderResp *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &qrl__get_last_block_header_resp__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   qrl__get_block_to_mine_req__init
                     (Qrl__GetBlockToMineReq         *message)
{
  static const Qrl__GetBlockToMineReq init_value = QRL__GET_BLOCK_TO_MINE_REQ__INIT;
  *message = init_value;
}
size_t qrl__get_block_to_mine_req__get_packed_size
                     (const Qrl__GetBlockToMineReq *message)
{
  assert(message->base.descriptor == &qrl__get_block_to_mine_req__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t qrl__get_block_to_mine_req__pack
                     (const Qrl__GetBlockToMineReq *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &qrl__get_block_to_mine_req__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t qrl__get_block_to_mine_req__pack_to_buffer
                     (const Qrl__GetBlockToMineReq *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &qrl__get_block_to_mine_req__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Qrl__GetBlockToMineReq *
       qrl__get_block_to_mine_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Qrl__GetBlockToMineReq *)
     protobuf_c_message_unpack (&qrl__get_block_to_mine_req__descriptor,
                                allocator, len, data);
}
void   qrl__get_block_to_mine_req__free_unpacked
                     (Qrl__GetBlockToMineReq *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &qrl__get_block_to_mine_req__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   qrl__get_block_to_mine_resp__init
                     (Qrl__GetBlockToMineResp         *message)
{
  static const Qrl__GetBlockToMineResp init_value = QRL__GET_BLOCK_TO_MINE_RESP__INIT;
  *message = init_value;
}
size_t qrl__get_block_to_mine_resp__get_packed_size
                     (const Qrl__GetBlockToMineResp *message)
{
  assert(message->base.descriptor == &qrl__get_block_to_mine_resp__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t qrl__get_block_to_mine_resp__pack
                     (const Qrl__GetBlockToMineResp *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &qrl__get_block_to_mine_resp__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t qrl__get_block_to_mine_resp__pack_to_buffer
                     (const Qrl__GetBlockToMineResp *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &qrl__get_block_to_mine_resp__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Qrl__GetBlockToMineResp *
       qrl__get_block_to_mine_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Qrl__GetBlockToMineResp *)
     protobuf_c_message_unpack (&qrl__get_block_to_mine_resp__descriptor,
                                allocator, len, data);
}
void   qrl__get_block_to_mine_resp__free_unpacked
                     (Qrl__GetBlockToMineResp *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &qrl__get_block_to_mine_resp__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   qrl__submit_mined_block_req__init
                     (Qrl__SubmitMinedBlockReq         *message)
{
  static const Qrl__SubmitMinedBlockReq init_value = QRL__SUBMIT_MINED_BLOCK_REQ__INIT;
  *message = init_value;
}
size_t qrl__submit_mined_block_req__get_packed_size
                     (const Qrl__SubmitMinedBlockReq *message)
{
  assert(message->base.descriptor == &qrl__submit_mined_block_req__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t qrl__submit_mined_block_req__pack
                     (const Qrl__SubmitMinedBlockReq *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &qrl__submit_mined_block_req__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t qrl__submit_mined_block_req__pack_to_buffer
                     (const Qrl__SubmitMinedBlockReq *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &qrl__submit_mined_block_req__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Qrl__SubmitMinedBlockReq *
       qrl__submit_mined_block_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Qrl__SubmitMinedBlockReq *)
     protobuf_c_message_unpack (&qrl__submit_mined_block_req__descriptor,
                                allocator, len, data);
}
void   qrl__submit_mined_block_req__free_unpacked
                     (Qrl__SubmitMinedBlockReq *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &qrl__submit_mined_block_req__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   qrl__submit_mined_block_resp__init
                     (Qrl__SubmitMinedBlockResp         *message)
{
  static const Qrl__SubmitMinedBlockResp init_value = QRL__SUBMIT_MINED_BLOCK_RESP__INIT;
  *message = init_value;
}
size_t qrl__submit_mined_block_resp__get_packed_size
                     (const Qrl__SubmitMinedBlockResp *message)
{
  assert(message->base.descriptor == &qrl__submit_mined_block_resp__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t qrl__submit_mined_block_resp__pack
                     (const Qrl__SubmitMinedBlockResp *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &qrl__submit_mined_block_resp__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t qrl__submit_mined_block_resp__pack_to_buffer
                     (const Qrl__SubmitMinedBlockResp *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &qrl__submit_mined_block_resp__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Qrl__SubmitMinedBlockResp *
       qrl__submit_mined_block_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Qrl__SubmitMinedBlockResp *)
     protobuf_c_message_unpack (&qrl__submit_mined_block_resp__descriptor,
                                allocator, len, data);
}
void   qrl__submit_mined_block_resp__free_unpacked
                     (Qrl__SubmitMinedBlockResp *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &qrl__submit_mined_block_resp__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor qrl__get_block_mining_compatible_req__field_descriptors[1] =
{
  {
    "height",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetBlockMiningCompatibleReq, height),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned qrl__get_block_mining_compatible_req__field_indices_by_name[] = {
  0,   /* field[0] = height */
};
static const ProtobufCIntRange qrl__get_block_mining_compatible_req__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor qrl__get_block_mining_compatible_req__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "qrl.GetBlockMiningCompatibleReq",
  "GetBlockMiningCompatibleReq",
  "Qrl__GetBlockMiningCompatibleReq",
  "qrl",
  sizeof(Qrl__GetBlockMiningCompatibleReq),
  1,
  qrl__get_block_mining_compatible_req__field_descriptors,
  qrl__get_block_mining_compatible_req__field_indices_by_name,
  1,  qrl__get_block_mining_compatible_req__number_ranges,
  (ProtobufCMessageInit) qrl__get_block_mining_compatible_req__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor qrl__get_last_block_header_req__field_descriptors[1] =
{
  {
    "height",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetLastBlockHeaderReq, height),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned qrl__get_last_block_header_req__field_indices_by_name[] = {
  0,   /* field[0] = height */
};
static const ProtobufCIntRange qrl__get_last_block_header_req__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor qrl__get_last_block_header_req__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "qrl.GetLastBlockHeaderReq",
  "GetLastBlockHeaderReq",
  "Qrl__GetLastBlockHeaderReq",
  "qrl",
  sizeof(Qrl__GetLastBlockHeaderReq),
  1,
  qrl__get_last_block_header_req__field_descriptors,
  qrl__get_last_block_header_req__field_indices_by_name,
  1,  qrl__get_last_block_header_req__number_ranges,
  (ProtobufCMessageInit) qrl__get_last_block_header_req__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor qrl__get_block_mining_compatible_resp__field_descriptors[2] =
{
  {
    "blockheader",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetBlockMiningCompatibleResp, blockheader),
    &qrl__block_header__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "blockmetadata",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetBlockMiningCompatibleResp, blockmetadata),
    &qrl__block_meta_data__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned qrl__get_block_mining_compatible_resp__field_indices_by_name[] = {
  0,   /* field[0] = blockheader */
  1,   /* field[1] = blockmetadata */
};
static const ProtobufCIntRange qrl__get_block_mining_compatible_resp__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor qrl__get_block_mining_compatible_resp__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "qrl.GetBlockMiningCompatibleResp",
  "GetBlockMiningCompatibleResp",
  "Qrl__GetBlockMiningCompatibleResp",
  "qrl",
  sizeof(Qrl__GetBlockMiningCompatibleResp),
  2,
  qrl__get_block_mining_compatible_resp__field_descriptors,
  qrl__get_block_mining_compatible_resp__field_indices_by_name,
  1,  qrl__get_block_mining_compatible_resp__number_ranges,
  (ProtobufCMessageInit) qrl__get_block_mining_compatible_resp__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor qrl__get_last_block_header_resp__field_descriptors[6] =
{
  {
    "difficulty",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetLastBlockHeaderResp, difficulty),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "height",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetLastBlockHeaderResp, height),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "timestamp",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetLastBlockHeaderResp, timestamp),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "reward",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetLastBlockHeaderResp, reward),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hash",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetLastBlockHeaderResp, hash),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "depth",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetLastBlockHeaderResp, depth),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned qrl__get_last_block_header_resp__field_indices_by_name[] = {
  5,   /* field[5] = depth */
  0,   /* field[0] = difficulty */
  4,   /* field[4] = hash */
  1,   /* field[1] = height */
  3,   /* field[3] = reward */
  2,   /* field[2] = timestamp */
};
static const ProtobufCIntRange qrl__get_last_block_header_resp__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 6 }
};
const ProtobufCMessageDescriptor qrl__get_last_block_header_resp__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "qrl.GetLastBlockHeaderResp",
  "GetLastBlockHeaderResp",
  "Qrl__GetLastBlockHeaderResp",
  "qrl",
  sizeof(Qrl__GetLastBlockHeaderResp),
  6,
  qrl__get_last_block_header_resp__field_descriptors,
  qrl__get_last_block_header_resp__field_indices_by_name,
  1,  qrl__get_last_block_header_resp__number_ranges,
  (ProtobufCMessageInit) qrl__get_last_block_header_resp__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor qrl__get_block_to_mine_req__field_descriptors[1] =
{
  {
    "wallet_address",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetBlockToMineReq, wallet_address),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned qrl__get_block_to_mine_req__field_indices_by_name[] = {
  0,   /* field[0] = wallet_address */
};
static const ProtobufCIntRange qrl__get_block_to_mine_req__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor qrl__get_block_to_mine_req__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "qrl.GetBlockToMineReq",
  "GetBlockToMineReq",
  "Qrl__GetBlockToMineReq",
  "qrl",
  sizeof(Qrl__GetBlockToMineReq),
  1,
  qrl__get_block_to_mine_req__field_descriptors,
  qrl__get_block_to_mine_req__field_indices_by_name,
  1,  qrl__get_block_to_mine_req__number_ranges,
  (ProtobufCMessageInit) qrl__get_block_to_mine_req__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor qrl__get_block_to_mine_resp__field_descriptors[5] =
{
  {
    "blocktemplate_blob",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetBlockToMineResp, blocktemplate_blob),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "difficulty",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetBlockToMineResp, difficulty),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "height",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetBlockToMineResp, height),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "reserved_offset",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetBlockToMineResp, reserved_offset),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "seed_hash",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Qrl__GetBlockToMineResp, seed_hash),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned qrl__get_block_to_mine_resp__field_indices_by_name[] = {
  0,   /* field[0] = blocktemplate_blob */
  1,   /* field[1] = difficulty */
  2,   /* field[2] = height */
  3,   /* field[3] = reserved_offset */
  4,   /* field[4] = seed_hash */
};
static const ProtobufCIntRange qrl__get_block_to_mine_resp__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor qrl__get_block_to_mine_resp__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "qrl.GetBlockToMineResp",
  "GetBlockToMineResp",
  "Qrl__GetBlockToMineResp",
  "qrl",
  sizeof(Qrl__GetBlockToMineResp),
  5,
  qrl__get_block_to_mine_resp__field_descriptors,
  qrl__get_block_to_mine_resp__field_indices_by_name,
  1,  qrl__get_block_to_mine_resp__number_ranges,
  (ProtobufCMessageInit) qrl__get_block_to_mine_resp__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor qrl__submit_mined_block_req__field_descriptors[1] =
{
  {
    "blob",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Qrl__SubmitMinedBlockReq, blob),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned qrl__submit_mined_block_req__field_indices_by_name[] = {
  0,   /* field[0] = blob */
};
static const ProtobufCIntRange qrl__submit_mined_block_req__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor qrl__submit_mined_block_req__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "qrl.SubmitMinedBlockReq",
  "SubmitMinedBlockReq",
  "Qrl__SubmitMinedBlockReq",
  "qrl",
  sizeof(Qrl__SubmitMinedBlockReq),
  1,
  qrl__submit_mined_block_req__field_descriptors,
  qrl__submit_mined_block_req__field_indices_by_name,
  1,  qrl__submit_mined_block_req__number_ranges,
  (ProtobufCMessageInit) qrl__submit_mined_block_req__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor qrl__submit_mined_block_resp__field_descriptors[1] =
{
  {
    "error",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(Qrl__SubmitMinedBlockResp, error),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned qrl__submit_mined_block_resp__field_indices_by_name[] = {
  0,   /* field[0] = error */
};
static const ProtobufCIntRange qrl__submit_mined_block_resp__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor qrl__submit_mined_block_resp__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "qrl.SubmitMinedBlockResp",
  "SubmitMinedBlockResp",
  "Qrl__SubmitMinedBlockResp",
  "qrl",
  sizeof(Qrl__SubmitMinedBlockResp),
  1,
  qrl__submit_mined_block_resp__field_descriptors,
  qrl__submit_mined_block_resp__field_indices_by_name,
  1,  qrl__submit_mined_block_resp__number_ranges,
  (ProtobufCMessageInit) qrl__submit_mined_block_resp__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCMethodDescriptor qrl__mining_api__method_descriptors[4] =
{
  { "GetBlockMiningCompatible", &qrl__get_block_mining_compatible_req__descriptor, &qrl__get_block_mining_compatible_resp__descriptor },
  { "GetLastBlockHeader", &qrl__get_last_block_header_req__descriptor, &qrl__get_last_block_header_resp__descriptor },
  { "GetBlockToMine", &qrl__get_block_to_mine_req__descriptor, &qrl__get_block_to_mine_resp__descriptor },
  { "SubmitMinedBlock", &qrl__submit_mined_block_req__descriptor, &qrl__submit_mined_block_resp__descriptor },
};
const unsigned qrl__mining_api__method_indices_by_name[] = {
  0,        /* GetBlockMiningCompatible */
  2,        /* GetBlockToMine */
  1,        /* GetLastBlockHeader */
  3         /* SubmitMinedBlock */
};
const ProtobufCServiceDescriptor qrl__mining_api__descriptor =
{
  PROTOBUF_C__SERVICE_DESCRIPTOR_MAGIC,
  "qrl.MiningAPI",
  "MiningAPI",
  "Qrl__MiningAPI",
  "qrl",
  4,
  qrl__mining_api__method_descriptors,
  qrl__mining_api__method_indices_by_name
};
void qrl__mining_api__get_block_mining_compatible(ProtobufCService *service,
                                                  const Qrl__GetBlockMiningCompatibleReq *input,
                                                  Qrl__GetBlockMiningCompatibleResp_Closure closure,
                                                  void *closure_data)
{
  assert(service->descriptor == &qrl__mining_api__descriptor);
  service->invoke(service, 0, (const ProtobufCMessage *) input, (ProtobufCClosure) closure, closure_data);
}
void qrl__mining_api__get_last_block_header(ProtobufCService *service,
                                            const Qrl__GetLastBlockHeaderReq *input,
                                            Qrl__GetLastBlockHeaderResp_Closure closure,
                                            void *closure_data)
{
  assert(service->descriptor == &qrl__mining_api__descriptor);
  service->invoke(service, 1, (const ProtobufCMessage *) input, (ProtobufCClosure) closure, closure_data);
}
void qrl__mining_api__get_block_to_mine(ProtobufCService *service,
                                        const Qrl__GetBlockToMineReq *input,
                                        Qrl__GetBlockToMineResp_Closure closure,
                                        void *closure_data)
{
  assert(service->descriptor == &qrl__mining_api__descriptor);
  service->invoke(service, 2, (const ProtobufCMessage *) input, (ProtobufCClosure) closure, closure_data);
}
void qrl__mining_api__submit_mined_block(ProtobufCService *service,
                                         const Qrl__SubmitMinedBlockReq *input,
                                         Qrl__SubmitMinedBlockResp_Closure closure,
                                         void *closure_data)
{
  assert(service->descriptor == &qrl__mining_api__descriptor);
  service->invoke(service, 3, (const ProtobufCMessage *) input, (ProtobufCClosure) closure, closure_data);
}
void qrl__mining_api__init (Qrl__MiningAPI_Service *service,
                            Qrl__MiningAPI_ServiceDestroy destroy)
{
  protobuf_c_service_generated_init (&service->base,
                                     &qrl__mining_api__descriptor,
                                     (ProtobufCServiceDestroy) destroy);
}
