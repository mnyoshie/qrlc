#include <stdlib.h>
#include "include/qtypes.h"

void free_qvec(qvec_t *q){
  free(q->data);
  free(q);
}

qvec_t *malloc_qvec(size_t size){
  qvec_t *q = malloc(sizeof(*q));
  if (q == NULL)
    return NULL;
  q->len = size;
  q->data = malloc(size);
  if (q->data == NULL) {
    free(q);
    return NULL;
  }
  return q;
}
#endif
