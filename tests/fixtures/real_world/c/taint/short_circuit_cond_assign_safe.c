#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int run_checked(void) {
    char *label;
    if ((label = getenv("USER_LABEL")) == NULL || strlen(label) > 64)
        return 1;
    puts("label accepted");
    return system("date");
}
