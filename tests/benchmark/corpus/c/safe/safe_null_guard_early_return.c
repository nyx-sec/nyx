#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Every acquire is checked for failure; the failure branch holds nothing. */
int read_first(const char *p) {
    FILE *f = fopen(p, "r");
    if (f == NULL)
        return -1;
    int c = fgetc(f);
    fclose(f);
    return c;
}

char *dup_str(const char *s) {
    size_t n = strlen(s) + 1;
    char *b = malloc(n);
    if (!b)
        return NULL;
    memcpy(b, s, n);
    return b;
}
