#include <stdio.h>
#include <stdlib.h>

void env_in_condition_constant_sink(void) {
    char *label;
    if ((label = getenv("LABEL")) == NULL)
        return;
    (void)label;
    system("date");
}

void counter_in_loop_condition(void) {
    int i = 0;
    int n;
    while ((n = i++) < 3) {
        printf("%d\n", n);
    }
}
