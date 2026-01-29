/*
 * A fake function which will be executed
 * instead of a real one!
 */
#include <signal.h>

int some_function(int *a, int *b) {
  (void) b;

  return *a * *a;
}

__attribute__((constructor))
static void stop_after_loader(void)
{
    raise(SIGSTOP);
}
