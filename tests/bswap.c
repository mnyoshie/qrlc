#include <stdint.h>
#include <byteswap.h>

int main() {
  uint32_t a = (uint32_t)bswap_16(1);
  uint32_t b = (uint32_t)bswap_32(1);
  uint32_t c = (uint32_t)bswap_64(1);
  return 0;
}
