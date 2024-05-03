#ifndef SLOW_HASH_H
#define SLOW_HASH_H

extern void cn_slow_hash(const void *data, size_t length, char *hash,
                         int variant, int prehashed, uint64_t height);
#endif
