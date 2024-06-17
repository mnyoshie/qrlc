#include "base64.h"
#include "utils.h"
#include "log.h"

static int test_b64(const char *b64, size_t b64len) {
  size_t i = 0;
  size_t eqctr = 0;
  if (b64len % 4) return 1;

  for (; i < b64len; i++) {
    if (isalnum(b64[i])) continue;

    switch (b64[i]) {
      case '/':
      case '+':
        continue;
      default:;
    }
    break;
  }

  switch (b64len - i) {
    case 0:
    case 1:
    case 2:
      break;
    default:
      return 1;
  }
  for (; i < b64len; i++, eqctr++)
    if (b64[i] != '=') return 1;

  if (eqctr > 3) return 1;
  return 0;
}

qvec_t qrl_decode_base64(const char *b64) {
  base64_decodestate state_in;
  size_t b64len = strlen(b64);
  if (test_b64(b64, b64len)) {
    QLOGX(QLOG_ERROR, "invalid base64\n");
    return (qvec_t){.data = NULL, .len = 0};
  }

  size_t maxlen = base64_decode_maxlength(b64len);

  void *plain = calloc(1, maxlen);
  assert(plain != NULL);

  base64_init_decodestate(&state_in);

  size_t plainlen = base64_decode_block((char *)b64, b64len, plain, &state_in);
  assert(maxlen >= plainlen);
  // printf("m %zu l %zu\n", maxlen, plainlen);

  return (qvec_t){.data = plain, .len = plainlen};
}

char *qrl_encode_base64(const qvec_t *plain) {
  base64_encodestate state_in;

  base64_init_encodestate(&state_in);
  size_t maxlen = base64_encode_length(plain->len, &state_in) + 1;
  char *b64 = calloc(1, maxlen);
  assert(b64 != NULL);

  base64_init_encodestate(&state_in);
  size_t b64len =
      base64_encode_block((char *)plain->data, plain->len, b64, &state_in);
  b64len += base64_encode_blockend((char *)b64 + b64len, &state_in);
  assert(maxlen >= b64len);
  b64[b64len] = 0;

  return b64;
}
