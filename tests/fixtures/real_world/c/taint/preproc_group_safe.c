#include <stdio.h>
#include <stdlib.h>

#ifndef NO_SHELL_HELPER
void file_scope_group(void) {
    char *cmd = "ls -l";
    system(cmd);
}
#endif

void block_scope_group(void) {
    char *cmd;
#if defined(USE_ENV)
    cmd = "uptime";
#else
    cmd = "date";
#endif
    system(cmd);
}
