int main() {
  int n = 1;
  if (*(char*)&n == 1)
    return 2; /* little endian */
  return 3;
}
