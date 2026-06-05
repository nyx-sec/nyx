/* ClassMethod C fixture with a receiver pointer and recursive struct deps. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct ShellRunner {
    int enabled;
} ShellRunner;

typedef struct CommandRunner {
    ShellRunner *shell;
} CommandRunner;

typedef struct UserService {
    CommandRunner *runner;
} UserService;

void UserService_run(UserService *self, const char *input, size_t len) {
    (void)len;
    if (!self || !self->runner || !self->runner->shell) {
        return;
    }
    char buf[512];
    snprintf(buf, sizeof(buf), "true %s", input ? input : "");
    system(buf);
}
