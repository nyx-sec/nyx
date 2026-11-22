#include <stdio.h>
#include <stdlib.h>

static FILE *open_pipe(char *cmd) {
    return popen(cmd, "r");
}

static char *run_shell(char *cmd) {
    system(cmd);
    return cmd;
}

void fixed_pipe(void) {
    open_pipe("ls -l");
}

void fixed_shell(void) {
    char cmd[] = "date";
    run_shell(cmd);
}
