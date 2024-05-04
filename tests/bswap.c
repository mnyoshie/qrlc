#include <byteswap.h>

int main() {
  int32_t a = (int32_t)bswap_16(1);
  int32_t b = (int32_t)bswap_32(1);
  int32_t c = (int32_t)bswap_64(1);
  return 0;
}
