#include <cstdint>
#include <atomic>
int main() {
  std::atomic<uint64_t> a;
  a.is_lock_free();
}
