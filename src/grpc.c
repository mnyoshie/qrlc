/* grpc.c - a crude, homemade, grpc client without the extra fancy features.
 *
 * Copyright (c) 2023-2024 M. N. Yoshie
 *
 * Release under MIT License
 *
 * */

#include <assert.h>
#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "include/log.h"
#include "include/qrl.pb-c.h"
#include "include/utils.h"

// #define QRL_NODE_ADDRESS "localhost:8080"
#define QRL_NODE_ADDRESS "mainnet-1.automated.theqrl.org:19009"
#define GRPC_MAX_TRANSFER 5

/* we set url and payload and passed it to qrl_init_grpc_transfer */
struct grpc_transfer {
  volatile int is_used;
  int *volatile is_finished;
  /* used internally and set by curl. we don't care about that */
  CURL *curl_handle;
  struct curl_slist *slist;

  /* our url string terminated by NUL*/
  char *url;

  /* this is what we're going to send to the grpc server */

  /* this is the response */
  ProtobufCBinaryData *response;
};

static int qrl_curl_trace(CURL *handle, curl_infotype type, char *data,
                          size_t size, void *userp) {
  if (type == CURLINFO_TEXT) {
    QRL_LOG_EX(QRL_LOG_TRACE, data);
  } else if (type == CURLINFO_DATA_IN) {
    QRL_LOG_EX(QRL_LOG_TRACE, "handle: %p GRPC_IN %d bytes <========\n", (void*)handle, size);
    qrl_dump_ex(QRL_LOG_TRACE, data, size);
  } else if (type == CURLINFO_DATA_OUT) {
    QRL_LOG_EX(QRL_LOG_TRACE, "handle: %p GRPC_OUT %d bytes ========>\n", (void*)handle, size);
    qrl_dump_ex(QRL_LOG_TRACE, data, size);
  }

  return 0;
}

static size_t qrl_curl_writedata(void *data, size_t size, size_t nmemb,
                                 void *userdata) {
  size_t data_len = size * nmemb;
  /* Discard the data. Probably someone was just resolving the dest */
  if (userdata == NULL) return data_len;

  ProtobufCBinaryData *response = userdata;
  response->data = realloc(response->data, response->len + data_len);
  if (response->data == NULL) {
    QRL_LOG_EX(QRL_LOG_PANIC, "RECEIVED NULL!!!\n");
    return 0;
  }

  /* copy new data */
  memcpy(response->data + response->len, data, data_len);
  response->len += data_len;

  return data_len;
}

static struct grpc_transfer grpc_transfers[GRPC_MAX_TRANSFER];
static int grpc_running_transfers = 0;
volatile static int grpc_added_transfers = 0;
volatile static int grpc_is_shutdown = 0;
static CURLM *curl_multi_handle = NULL;
static pthread_mutex_t curl_multi_mutex = PTHREAD_MUTEX_INITIALIZER;

struct grpc_transfer *qrl_retrieve_grpc_transfer(CURL *handle) {
  for (int i = 0; i < GRPC_MAX_TRANSFER; i++) {
    if (grpc_transfers[i].curl_handle == handle) return grpc_transfers + i;
  }
  return NULL;
}

/* For goodness sake. Each of this parameter must be alive, until is_finish is set to 1.
 * Their lifetime must exist until is_finish is set to 1, which you can then safely free */
int qrl_add_grpc_transfer(char *url, ProtobufCBinaryData payload,
                          ProtobufCBinaryData *response,
                          int *volatile is_finished) {
  while (grpc_added_transfers >= GRPC_MAX_TRANSFER) {
  }


  CURL *curl_hnd = curl_easy_init();
  assert(curl_hnd != NULL);

  struct curl_slist *slist =
      curl_slist_append(NULL, "Content-Type: application/grpc+proto");
  assert(slist != NULL);
  {
    void *temp = curl_slist_append(slist, "TE: trailers");
    assert(temp != NULL);
    slist = temp;
    temp = curl_slist_append(slist, "Connection: keep-alive");
    assert(temp != NULL);
    slist = temp;
    temp = curl_slist_append(slist, "User-Agent: crude-grpc/0.0.0");
    assert(temp != NULL);
    slist = temp;
  }

  int cres = 0;
  cres += curl_easy_setopt(curl_hnd, CURLOPT_HTTP_VERSION,
                   CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
  cres += curl_easy_setopt(curl_hnd, CURLOPT_URL, url);
  cres += curl_easy_setopt(curl_hnd, CURLOPT_HTTPHEADER, slist);
  cres += curl_easy_setopt(curl_hnd, CURLOPT_POSTFIELDSIZE, payload.len);
  cres += curl_easy_setopt(curl_hnd, CURLOPT_COPYPOSTFIELDS, payload.data);
  cres += curl_easy_setopt(curl_hnd, CURLOPT_WRITEFUNCTION, qrl_curl_writedata);
  cres += curl_easy_setopt(curl_hnd, CURLOPT_WRITEDATA, response);

  cres += curl_easy_setopt(curl_hnd, CURLOPT_VERBOSE, 1L);
  cres += curl_easy_setopt(curl_hnd, CURLOPT_DEBUGFUNCTION, qrl_curl_trace);
  cres += curl_easy_setopt(curl_hnd, CURLOPT_DEBUGDATA, NULL);
  if (cres)
    assert(0);

  pthread_mutex_lock(&curl_multi_mutex);
  for (int i = 0; i < GRPC_MAX_TRANSFER; i++) {
    if (grpc_transfers[i].is_finished == NULL) {
      grpc_transfers[i].is_finished = is_finished;
      grpc_transfers[i].curl_handle = curl_hnd;
      grpc_transfers[i].slist = slist;
      grpc_transfers[i].url = url;
      grpc_transfers[i].response = response;
      curl_multi_add_handle(curl_multi_handle, curl_hnd);
      grpc_added_transfers++;
      QRL_LOG_EX(QRL_LOG_VERBOSE, "transfer added. handle: %p dest: %s\n",
                 (void *)curl_hnd, url);
      break;
    }
  }
  pthread_mutex_unlock(&curl_multi_mutex);
  return 0;
}

static void *start_grpc_client(void *curl_multi_handle) {
  do {
    pthread_mutex_lock(&curl_multi_mutex);
    CURLMcode mc =
        curl_multi_perform(curl_multi_handle, &grpc_running_transfers);
    if (grpc_running_transfers) {
      mc = curl_multi_poll(curl_multi_handle, NULL, 0, 1500, NULL);
    }
    pthread_mutex_unlock(&curl_multi_mutex);
    /* some transfers has finished? */
    if (grpc_added_transfers > grpc_running_transfers) {
      int msgs = 0;
      for (struct CURLMsg *curl_msg =
               curl_multi_info_read(curl_multi_handle, &msgs);
           curl_msg != NULL;
           curl_msg = curl_multi_info_read(curl_multi_handle, &msgs)) {
        switch (curl_msg->msg) {
          case CURLMSG_DONE: {
            struct grpc_transfer *transfer =
                qrl_retrieve_grpc_transfer(curl_msg->easy_handle);
            pthread_mutex_lock(&curl_multi_mutex);
            QRL_LOG_EX(QRL_LOG_VERBOSE, "transfer done. handle: %p dest: %s\n",
                       (void *)curl_msg->easy_handle, transfer->url);

	    /* the transfer is done. remove it */
            curl_multi_remove_handle(curl_multi_handle, transfer->curl_handle);
            curl_slist_free_all(transfer->slist);
            transfer->slist = NULL;
	    curl_easy_cleanup(transfer->curl_handle);
            transfer->curl_handle = NULL;
	
            *(transfer->is_finished) = 1;
            transfer->is_finished = NULL;

            transfer->url = NULL;
            grpc_added_transfers--;
            pthread_mutex_unlock(&curl_multi_mutex);
            /* TODO: clean */
          } break;
          default:
            QRL_LOG_EX(QRL_LOG_ERROR, "unknown curl msg %d\n", curl_msg->msg);
            break;
        }
      }
    }

    if (grpc_is_shutdown) break;
    if (mc) {
      QRL_LOG("error curl %d\n", mc);
      break;
    }

  } while (1);

  /* check if some transfers are not completed. */
  for (int i = 0; i < GRPC_MAX_TRANSFER; i++) {
    if (grpc_transfers[i].curl_handle != NULL) {
      curl_multi_remove_handle(curl_multi_handle, grpc_transfers[i].curl_handle);
      curl_slist_free_all(grpc_transfers[i].slist);
      grpc_transfers[i].slist = NULL;
      curl_easy_cleanup(grpc_transfers[i].curl_handle);
      grpc_transfers[i].curl_handle = NULL;
    }

  }
  curl_multi_cleanup(curl_multi_handle);
  curl_multi_handle = NULL;
  curl_global_cleanup();
  QRL_LOG_EX(QRL_LOG_TRACE, "grpc_shutdown\n");
  return NULL;
}

pthread_t qrl_init_grpc() {
  CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (res != CURLE_OK) {
    QRL_LOG_EX(QRL_LOG_ERROR, "%s\n", curl_easy_strerror(res));
    return 1;
  }

  curl_multi_handle = curl_multi_init();
  if (curl_multi_handle == NULL) {
    return 1;
  }

  curl_multi_setopt(curl_multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

  /* dummy request just to resolve the domain */
  static int is_finish = 0;
  static char *dest = "http://" QRL_NODE_ADDRESS "/qrl.PublicAPI/GetHeight";
  qrl_add_grpc_transfer(dest,
                        (ProtobufCBinaryData){5, (uint8_t[]){0, 0, 0, 0, 0, 0}},
                        NULL, &is_finish);

  pthread_t thread;
  pthread_create(&thread, NULL, start_grpc_client, curl_multi_handle);
  return thread;
}

void qrl_shutdown_grpc() {
  QRL_LOG_EX(QRL_LOG_TRACE, "grpc_shutdown requested\n");
  grpc_is_shutdown = 1;
}

static int qrl_send_grpc(char *url, ProtobufCBinaryData data_in,
                         ProtobufCBinaryData *data_out) {
  CURL *curl_hnd;
  CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
  int ret = 0;
  if (res != CURLE_OK) {
    fputs(curl_easy_strerror(res), stderr);
    return 1;
  }

  curl_hnd = curl_easy_init();
  assert(curl_hnd != NULL);

  struct curl_slist *slist =
      curl_slist_append(NULL, "Content-Type: application/grpc+proto");
  assert(slist != NULL);
  {
    void *temp = curl_slist_append(slist, "TE: trailers");
    assert(temp != NULL);
    slist = temp;
    temp = curl_slist_append(slist, "Connection: keep-alive");
    assert(temp != NULL);
    slist = temp;
    temp = curl_slist_append(slist, "User-Agent: crude-grpc/0.0.0");
    assert(temp != NULL);
    slist = temp;
  }

  curl_easy_setopt(curl_hnd, CURLOPT_HTTP_VERSION,
                   CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
  curl_easy_setopt(curl_hnd, CURLOPT_URL, url);
  curl_easy_setopt(curl_hnd, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl_hnd, CURLOPT_POSTFIELDSIZE, data_in.len);
  curl_easy_setopt(curl_hnd, CURLOPT_COPYPOSTFIELDS, data_in.data);
  curl_easy_setopt(curl_hnd, CURLOPT_WRITEFUNCTION, qrl_curl_writedata);
  ProtobufCBinaryData response = {0, NULL};
  curl_easy_setopt(curl_hnd, CURLOPT_WRITEDATA, &response);

  curl_easy_setopt(curl_hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl_hnd, CURLOPT_DEBUGFUNCTION, qrl_curl_trace);
  curl_easy_setopt(curl_hnd, CURLOPT_DEBUGDATA, NULL);
  curl_easy_setopt(curl_hnd, CURLOPT_FORBID_REUSE, 1);

  res = curl_easy_perform(curl_hnd);
  if (res == CURLE_OK) {
    char *ct = NULL;
    res = curl_easy_getinfo(curl_hnd, CURLINFO_CONTENT_TYPE, &ct);
    if (strcmp("application/grpc", ct) &&
        strcmp("application/grpc+proto", ct)) {
      QRL_LOG_EX(QRL_LOG_ERROR,
                 "expecting content-type of 'application/grpc' or "
                 "'application/grpc+proto, but got '%s'\n",
                 ct);
      if (response.data != NULL) free(response.data);
      ret = 1;
      goto exit;
    }

    if (response.len <= 5) {
      QRL_LOG_EX(QRL_LOG_ERROR,
                 "message sent successfully, but receive no data\n");
      if (response.data != NULL) free(response.data);
      ret = 1;
      goto exit;
    }

    if (response.len != QRL_BSWAP32(*(uint32_t *)(response.data + 1)) + 5) {
      QRL_LOG_EX(QRL_LOG_ERROR,
                 "received malformed grpc stream. received %d bytes. but "
                 "*(uint32_t)(response.data+1) is %d bytes\n,",
                 response.len, QRL_BSWAP32(*(uint32_t *)(response.data + 1)));
      if (response.data != NULL) free(response.data);
      ret = 1;
      goto exit;
    }

    *data_out = response;
  } else {
    QRL_LOG_EX(QRL_LOG_ERROR, "%s", curl_easy_strerror(res));
    ret = 1;
  }

exit:
  curl_slist_free_all(slist);
  curl_easy_cleanup(curl_hnd);
  curl_global_cleanup();

  return ret;
}
Qrl__GetBlockByNumberResp *qrl_get_block_by_number(
    Qrl__GetBlockByNumberReq request) {
  size_t req_size = qrl__get_block_by_number_req__get_packed_size(&request);
  uint8_t *req_buf = malloc(1 + 4 + req_size);

  // In grpc wireformat, the first byte signifies the compression.
  // the next 4 bytes (in big endian) signifies the length of the data.
  // This is then followed by the data.
  req_buf[0] = 0;  // not compressed
  memcpy(req_buf + 1, &(uint32_t){QRL_BSWAP32((uint32_t)req_size)}, 4);
  qrl__get_block_by_number_req__pack(&request, 1 + 4 + req_buf);

  ProtobufCBinaryData response_proto;
  if (qrl_send_grpc(
          "http://" QRL_NODE_ADDRESS "/qrl.PublicAPI/GetBlockByNumber",
          (ProtobufCBinaryData){req_size + 5, req_buf}, &response_proto)) {
    free(req_buf);
    return NULL;
  }

  Qrl__GetBlockByNumberResp *response = qrl__get_block_by_number_resp__unpack(
      NULL, response_proto.len - 5, response_proto.data + 5);

  free(req_buf);
  free(response_proto.data);
  return response;
}

Qrl__GetHeightResp *qrl_get_height(Qrl__GetHeightReq request) {
  size_t req_size = qrl__get_height_req__get_packed_size(&request);
  assert(req_size == 0);
  uint8_t *req_buf = malloc(1 + 4 + req_size);

  // In grpc wireformat, the first byte signifies the compression.
  // the next 4 bytes (in big endian) signifies the length of the data.
  // This is then followed by the data.
  req_buf[0] = 0;  // not compressed
  memcpy(req_buf + 1, &(uint32_t){QRL_BSWAP32((uint32_t)req_size)}, 4);
  qrl__get_height_req__pack(&request, 1 + 4 + req_buf);

  ProtobufCBinaryData response_proto;
  if (qrl_send_grpc("http://" QRL_NODE_ADDRESS "/qrl.PublicAPI/GetHeight",
                    (ProtobufCBinaryData){req_size + 5, req_buf},
                    &response_proto)) {
    free(req_buf);
    return NULL;
  }

  Qrl__GetHeightResp *response = qrl__get_height_resp__unpack(
      NULL, response_proto.len - 5, response_proto.data + 5);

  free(req_buf);
  free(response_proto.data);
  return response;
}
