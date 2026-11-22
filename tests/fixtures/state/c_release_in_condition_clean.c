#include <stdio.h>

void die(const char *m);

void close_in_if(const char *name) {
    FILE *f = fopen(name, "w");
    if (!f)
        return;
    fprintf(f, "x\n");
    if (fclose(f))
        die("could not finish");
}

int close_in_if_goto(const char *name) {
    FILE *f = fopen(name, "w");
    if (!f)
        return -1;
    fprintf(f, "x\n");
    if (fclose(f)) {
        f = NULL;
        goto werr;
    }
    return 0;
werr:
    if (f)
        fclose(f);
    return -1;
}

int close_compared(const char *name) {
    FILE *f = fopen(name, "w");
    if (!f)
        return -1;
    if (fclose(f) == EOF)
        return -1;
    return 0;
}
