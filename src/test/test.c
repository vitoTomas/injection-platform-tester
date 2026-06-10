#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) static int some_function(int *a, int *b)
{
  volatile int res;

  res = *a + *b * *b + *a / 2;
  return res;
}

__attribute__((noinline)) int some_global_function(int *a)
{
  int square;

  square = *a * *a;
  return square;
}

__attribute__((noinline)) int param_printer(int a, int b, int c, int d, int e)
{
  printf("Function got the following params: %d %d %d %d %d\n", a, b, c, d, e);
  return 0;
}

int main() {
  int res, square;
  int a = 4, b = 5;
  int p1 = 1, p2 = 2, p3 = 3, p4 = 4, p5 = 5;
  printf("Started the test program...\n");

  res = some_function(&a, &b);
  square = some_global_function(&a);

  printf("Result is: %d and %d\n", res, square);

  printf("Sending following parameters to the function: %d %d %d %d %d\n",
         p1, p2, p3, p4, p5);
  param_printer(p1, p2, p3, p4, p5);

  return 0;
}
