#include <stdio.h>
#include <stdlib.h>

void die(const char *m);

/* The release is the condition of an if: it runs before either branch. */
void close_in_if(const char *name) {
    FILE *f = fopen(name, "w");
    if (!f)
        return;
    fprintf(f, "x\n");
    if (fclose(f))
        die("could not finish");
}

/* A failed fclose still released the handle; the error path clears the name
 * so the cleanup label does not close it a second time. */
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

/* No release at all: still a leak. */
void never_closed(const char *name) {
    FILE *f = fopen(name, "w");
    if (!f)
        return;
    fprintf(f, "x\n");
}

/* The release only runs when `ok` is set, so the other path leaks. */
void close_behind_and(const char *name, int ok) {
    FILE *f = fopen(name, "w");
    if (!f)
        return;
    if (ok && fclose(f))
        die("could not finish");
}
