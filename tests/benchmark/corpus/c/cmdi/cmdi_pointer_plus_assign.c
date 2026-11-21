#include <stdlib.h>
#include <stdio.h>

/* Skipping a prefix with `p += 1` still points into the environment value. */
int main() {
    char *p = getenv("USER_CMD");
    p += 1;
    system(p);
    return 0;
}
