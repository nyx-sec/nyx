/* Benign control for the recursive C receiver fixture. */
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
    (void)input;
    (void)len;
    if (!self || !self->runner || !self->runner->shell) {
        return;
    }
    system("true");
}
