#include <stdlib.h>
#include <unistd.h>

int run_default(void) {
    char *cmd = getenv("USER_CMD");
    if ((cmd = "uptime") == NULL)
        return 1;
    return execvp(cmd, NULL);
}
