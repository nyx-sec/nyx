#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int run_checked(void) {
    char *cmd;
    if ((cmd = getenv("USER_CMD")) == NULL || strlen(cmd) > 64)
        return 1;
    return system(cmd);
}
