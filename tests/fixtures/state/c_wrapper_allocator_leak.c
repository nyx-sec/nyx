#include <stdlib.h>

void *xmalloc(size_t n);
void *g_malloc(size_t n);

/* C keeps suffix matching for prefixed allocators, so both leaks are
   still found.  Expected: state-resource-leak (twice). */
void leak_x(size_t n) {
    char *p = xmalloc(n);
    p[0] = 0;
}

void leak_g(size_t n) {
    char *q = g_malloc(n);
    q[0] = 0;
}
