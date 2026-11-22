#include <stdio.h>
#include <stdlib.h>

void literal_in_condition(void) {
    char *cmd;
    if ((cmd = "ls -l") == NULL)
        return;
    system(cmd);
}

void counter_in_loop_condition(void) {
    int i = 0;
    int n;
    while ((n = i++) < 3) {
        printf("%d\n", n);
    }
}
