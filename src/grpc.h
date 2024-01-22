#ifndef QRL_GRPC_H
#define QRL_GRPC_H

#include <assert.h>
#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "include/log.h"
#include "include/qrl.pb-c.h"
#include "include/utils.h"

#ifdef QRL_GRPC_DECLARE
#define QRL_GRPC_EXTERN
#else
#define QRL_GRPC_EXTERN extern
#endif

/* For goodness sake. Each of this parameter must be alive until is_finish is set to 1.
 * Their lifetime must exist until is_finish is set to 1, which you can then safely free */
QRL_GRPC_EXTERN int qrl_add_grpc_transfer(char *url, ProtobufCBinaryData payload,
                          ProtobufCBinaryData *response,
                          int *volatile is_finished);
QRL_GRPC_EXTERN int qrl_init_grpc(void);

QRL_GRPC_EXTERN void qrl_shutdown_grpc();

QRL_GRPC_EXTERN  Qrl__GetBlockByNumberResp *qrl_get_block_by_number(
    Qrl__GetBlockByNumberReq request);

QRL_GRPC_EXTERN Qrl__GetHeightResp *qrl_get_height(Qrl__GetHeightReq request);
#endif /* QRL_GRPC_H */
