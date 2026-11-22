#include <stdio.h>
#include <stdlib.h>

#ifndef NO_SHELL_HELPER
void file_scope_group(void) {
    char *cmd = getenv("USER_CMD");
    system(cmd);
}
#endif

void block_scope_group(void) {
    char *cmd;
#if defined(USE_ENV)
    cmd = getenv("USER_CMD");
#else
    cmd = getenv("FALLBACK_CMD");
#endif
    system(cmd);
}
