#include <stdio.h>
#include <stdlib.h>

#ifndef NO_SHELL_HELPER
void file_scope_group(void) {
    char *label = getenv("LABEL");
    (void)label;
    system("ls -l");
}
#endif

void block_scope_group(void) {
    char *cmd;
#if defined(USE_ENV)
    cmd = "uptime";
#else
    cmd = "date";
#endif
    printf("running %s\n", cmd);
    system("date");
}
