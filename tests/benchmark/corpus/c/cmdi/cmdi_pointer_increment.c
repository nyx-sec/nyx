#include <stdlib.h>
#include <stdio.h>

/* `p++` skips one character but still points into the environment value. */
int main() {
    char *p = getenv("USER_CMD");
    p++;
    system(p);
    return 0;
}
