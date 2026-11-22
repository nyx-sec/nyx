#include <stdio.h>

struct S { FILE *f; int n; };
void reg(struct S *s);

/* The handle moves into the returned aggregate. */
struct S make_designated(const char *path) {
    FILE *f = fopen(path, "r");
    struct S s = { .f = f, .n = 1 };
    return s;
}

/* The handle moves into an aggregate that is registered. */
void make_registered(const char *path) {
    FILE *f = fopen(path, "r");
    struct S s = { f, 1 };
    reg(&s);
}

/* No aggregate: the handle is never closed. */
void plain_leak(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    fprintf(f, "x");
}
