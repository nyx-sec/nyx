#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Factories: the NULL branch returns NULL (nothing allocated), the success
   branch hands the handle to the caller.  Expected: no resource findings. */

char *dup_str(const char *s) {
    char *b = malloc(strlen(s) + 1);
    if (b == NULL) return NULL;
    strcpy(b, s);
    return b;
}

FILE *open_log(const char *p) {
    FILE *f = fopen(p, "a");
    if (!f) {
        return NULL;
    }
    fputs("start\n", f);
    return f;
}
