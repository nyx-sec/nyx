#include <stdio.h>
#include <stdlib.h>

/* Pointer-returning definitions: the declarator is pointer_declarator ->
   function_declarator, so the parameter list is one level deeper. */
static FILE *open_pipe(char *cmd) {
    return popen(cmd, "r");
}

static char *run_shell(char *cmd) {
    system(cmd);
    return cmd;
}

void from_env_pipe(void) {
    char *cmd = getenv("PIPE_CMD");
    open_pipe(cmd);
}

void from_env_shell(void) {
    char *cmd = getenv("SHELL_CMD");
    run_shell(cmd);
}
