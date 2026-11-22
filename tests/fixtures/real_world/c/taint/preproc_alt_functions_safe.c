#include <stdlib.h>

#ifdef PORTABLE_BUILD
static void run_job(char *cmd) {
    (void)cmd;
}
#else
static void run_job(char *cmd) {
    (void)cmd;
    system("date");
}
#endif

int main(void) {
    char *job = getenv("JOB_CMD");
    run_job(job);
    return 0;
}
