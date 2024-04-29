#include <stdlib.h>
#include <assert.h>

#include "include/types.h"

/* free qvec */
void fqvec(qvec_t *q){
  free(q->data);
  free(q);
}

/* delete qvec */
void dqvec(qvec_t q){
  free(q.data);
  q.len = 0;
}

qvec_t *malloc_qvec(size_t size){
  qvec_t *q = malloc(sizeof(*q));
  assert(q != NULL);

  q->len = size;
  q->data = malloc(size);

  assert(q->data != NULL);
  return q;
}

qvec_t new_qvec(size_t size){
  qu8 *q = calloc(1, size);
  assert(q != NULL);

  return (qvec_t){.data=q, .len=size};
}
