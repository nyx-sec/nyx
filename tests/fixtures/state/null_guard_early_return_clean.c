#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Each acquire is checked for failure and the failure branch returns early.
   Nothing was produced on that branch, so no close is owed there.
   Expected: no resource findings. */

int eq_null(const char *p) {
    FILE *f = fopen(p, "r");
    if (f == NULL) return -1;
    fgetc(f);
    fclose(f);
    return 0;
}

int not_handle(const char *p) {
    FILE *f = fopen(p, "r");
    if (!f) {
        return -1;
    }
    fgetc(f);
    fclose(f);
    return 0;
}

int null_on_left(const char *p) {
    FILE *f = fopen(p, "r");
    if (NULL == f) return -1;
    fgetc(f);
    fclose(f);
    return 0;
}

int ne_null_block(const char *p) {
    FILE *f = fopen(p, "r");
    if (f != NULL) {
        fgetc(f);
        fclose(f);
    }
    return 0;
}

int buffer(int n) {
    char *b = malloc(n);
    if (!b) return -1;
    memset(b, 0, n);
    free(b);
    return 0;
}
