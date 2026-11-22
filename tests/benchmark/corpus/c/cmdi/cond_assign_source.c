#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void env_in_condition(void) {
    char *cmd;
    if ((cmd = getenv("USER_CMD")) == NULL)
        return;
    system(cmd);
}

void env_in_negated_condition(void) {
    char *cmd;
    if (!(cmd = getenv("USER_CMD")))
        return;
    system(cmd);
}

void read_in_loop_condition(void) {
    char buf[256];
    ssize_t n;
    while ((n = read(0, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        system(buf);
    }
}
