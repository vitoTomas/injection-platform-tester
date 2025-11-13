#include <stdio.h>

__attribute__((noinline)) static int some_function(int *a, int *b) {
  volatile int res;

  res = *a + *b * *b + *a / 2;
  return res;
}

__attribute__((noinline)) int some_global_function(int *a) {
  int square;

  square = *a * *a;
  return square;
}

int main() {
  int res, square;
  int a = 4, b = 5;
  printf("Started the test program...\n");

  res = some_function(&a, &b);
  square = some_global_function(&a);

  printf("Result is: %d and %d\n", res, square);
  return 0;
}
