#include <stdio.h>
#include <string.h>

int main(void) {
  unsigned char buf[1024];
  size_t n = fread(buf, 1, sizeof(buf), stdin);

  if (n >= 5) {
    for (size_t i = 0; i + 5 <= n; i++) {
      if (memcmp(buf + i, "CRASH", 5) == 0) {
        volatile int *p = (int *)0;
        *p = 1;
      }
    }
  }

  return 0;
}
