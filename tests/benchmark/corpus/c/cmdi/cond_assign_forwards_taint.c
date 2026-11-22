#include <stdlib.h>

int run_alias(void) {
    char *raw = getenv("USER_CMD");
    char *cmd = "uptime";
    if ((cmd = raw) == NULL)
        return 1;
    return system(cmd);
}
