#include <stdlib.h>

void alias_leak(void) {
    char *p = malloc(8);
    char *q = p;
    q[0] = 1;
}
