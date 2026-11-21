#include <stdio.h>

/* The NULL guard is fine, but the second early return leaks the open
   handle.  Expected: state-resource-leak-possible. */
int read_first(const char *p, int skip) {
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    if (skip) return -2;
    fgetc(f);
    fclose(f);
    return 0;
}
