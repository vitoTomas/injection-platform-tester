/*
 * A fake function which will be executed
 * instead of a real one!
 */
#include <stdio.h>
#include <signal.h>

static int cnt = 0;

int some_function(int *a, int *b) {
        (void) b;

        return *a * *a;
}

int clock_gettime(int id, struct timespec *tp)
{
        tp->tv_sec = 0;
        tp->tv_nsec = 0;

        return 0;
}

__attribute__((constructor))
static void stop_after_loader(void)
{
        raise(SIGSTOP);
}
