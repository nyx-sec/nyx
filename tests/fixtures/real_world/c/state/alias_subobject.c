#include <stdlib.h>

typedef struct { int flags; } ctx_t;
typedef struct { ctx_t c; int x; } actx_t;
typedef struct { int n; char **names; } change_t;
void fire(change_t *cc);

/* c points into ac; it is not a second owner of the allocation. */
actx_t *init_addr_of_field(void) {
    actx_t *ac = malloc(sizeof(*ac));
    if (!ac)
        return NULL;
    ctx_t *c = &(ac->c);
    c->flags = 1;
    return ac;
}

/* names is copied into a local aggregate and freed here. */
void init_struct_literal(int n) {
    char **names = malloc(sizeof(char *) * n);
    change_t cc = {.n = n, .names = names};
    fire(&cc);
    free(names);
}

/* A plain alias is the same handle, and nobody frees it. */
void alias_leak(void) {
    char *p = malloc(8);
    char *q = p;
    q[0] = 1;
}
