#include <stdlib.h>

typedef struct { int flags; } ctx_t;
typedef struct { ctx_t c; int x; } actx_t;
typedef struct { int n; char **names; } change_t;
void fire(change_t *cc);

actx_t *init_addr_of_field(void) {
    actx_t *ac = malloc(sizeof(*ac));
    if (!ac)
        return NULL;
    ctx_t *c = &(ac->c);
    c->flags = 1;
    return ac;
}

void init_struct_literal(int n) {
    char **names = malloc(sizeof(char *) * n);
    change_t cc = {.n = n, .names = names};
    fire(&cc);
    free(names);
}

void sub_pointer(void) {
    char *buf = malloc(16);
    char *end = buf + 16;
    *buf = 0;
    *end = 0;
    free(buf);
}

struct opts { const char *a; const char *b; };
struct node { int kind; };

const char *pick_by_kind(struct opts *opt) {
    struct node *n = malloc(sizeof(*n));
    const char *name;
    n->kind = 1;
    name = (n->kind == 2) ? opt->a : opt->b;
    free(n);
    return name;
}
