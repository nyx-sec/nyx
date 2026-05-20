/* Phase 19 (Track M.1) — class-method benign control for C. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void UserService_run(const char *input, size_t len) {
    (void)len;
    /* Uses execve via fork; the shell never sees `input`. */
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = { (char*)"/bin/echo", (char*)(input ? input : ""), NULL };
        execv("/bin/echo", argv);
        _exit(127);
    }
}
