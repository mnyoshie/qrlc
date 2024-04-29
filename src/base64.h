#ifndef QBASE64_H
#define QBASE64_H

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>

#include "include/b64/cdecode.h"
#include "include/b64/cencode.h"
#include "include/types.h"

extern qvec_t qrl_decode_base64(const char *b64);
extern char *qrl_encode_base64(const qvec_t *plain);

#endif
