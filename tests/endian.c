#include <stdio.h>

int main() {
  int n = 1;
  if (*(char*)&n == 1) {
    printf("little\n"); /* little endian */
    return 0;
  }
  printf("big\n");
  return 0;
}
