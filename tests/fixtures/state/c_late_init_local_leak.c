#include <stdio.h>

/* The handle is a local declared before it is assigned, so it is still
   owned here and leaks.  Expected: state-resource-leak. */
void late_init(const char *p) {
    FILE *f;
    f = fopen(p, "r");
    fgetc(f);
}
