#include <stdio.h>
#include <stdlib.h>

#define SNPRINTF2(str, len, fmt, a, b) snprintf((str), (len), (fmt), (a), (b))

void build_and_run(char *a, char *b) {
    char cmd[256];
    SNPRINTF2(cmd, sizeof(cmd), "echo %s %s", "x", "y");
    system(cmd);
}
