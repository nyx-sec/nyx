#include <stdio.h>

void die(const char *m);

void behind_and(const char *name, int ok) {
    FILE *f = fopen(name, "w");
    if (!f)
        return;
    if (ok && fclose(f))
        die("could not finish");
}

void never_closed(const char *name) {
    FILE *f = fopen(name, "w");
    if (!f)
        return;
    fprintf(f, "x\n");
}
