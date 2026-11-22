#include <stdlib.h>

/* The offset alias is never returned or released: still a leak. */
int offset_leak(size_t n) {
    char *sh = malloc(n + 8);
    char *s = sh + 8;
    s[0] = 1;
    return 0;
}
