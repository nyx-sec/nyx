#include <stdlib.h>

struct base { int fd; };
struct iter_int { struct base base; int n; };

static void iter_free(struct base *b) {
    free(b);
}

/* Factory returning an address of the first member: ownership goes to the caller. */
struct base *iter_begin(int fail) {
    struct iter_int *iter = calloc(1, sizeof(*iter));
    struct base *b = &iter->base;
    if (fail)
        goto error_out;
    return b;
error_out:
    iter_free(b);
    return NULL;
}

/* Header-offset alias returned to the caller. */
char *sds_new(size_t n) {
    void *sh = malloc(n + 8);
    char *s;
    if (sh == NULL)
        return NULL;
    s = (char *)sh + 8;
    return s;
}

char *sds_grow(char *s, size_t n) {
    void *sh = (char *)s - 8;
    void *newsh = realloc(sh, n + 8);
    if (newsh == NULL)
        return NULL;
    s = (char *)newsh + 8;
    return s;
}

/* Chained store: the value also lands in a field the caller owns. */
struct cfg_t { void *priv; };
void set_priv(struct cfg_t *cfg) {
    int *regs;
    regs = cfg->priv = malloc(16);
    regs[0] = 1;
}

/* A same-file function that frees its argument releases it. */
static void drop(char *p) {
    free(p);
}
int wrapped(int n) {
    char *p = malloc(10);
    if (!p)
        return 1;
    p[0] = (char)n;
    drop(p);
    return 0;
}
