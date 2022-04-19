#include <stdio.h>

long fibonacci(int n) {
  if (n <= 2) {
    return 1;
  }
  return fibonacci(n - 1) + fibonacci(n - 2);
}


int main(int argc, const char *argv[]) {
  printf("result: %ld\n", fibonacci(100));
  return 0;
}
