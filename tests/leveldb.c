#include <leveldb/c.h>

int main() {
  leveldb_t *db = leveldb_open(NULL, NULL, NULL);
  return 0;
}
