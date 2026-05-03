/*
 * c-safe-realrepo-001 — distilled from curl/lib/dynhds.c::entry_new
 * (and a similar shape in dozens of other curl/openssl/postgres/git
 * functions).  Pattern: a constructor allocates a parent struct then
 * assigns sub-buffer pointers (or transfers local-allocated buffers)
 * into struct fields, finally returning the parent.  The parent's
 * lifecycle is owned by the caller; the engine should not flag
 * `e->name`, `mem->buf`, etc., as "never closed".
 *
 * Engine fix (depth: structural — apply_assignment field-LHS gate):
 *   src/state/transfer.rs::apply_assignment skips ownership transfer
 *   when `defines` is a member expression (`.` or `->`).  The RHS is
 *   marked MOVED so the local-leak analysis treats the assignment as
 *   ownership transfer to the parent struct, while the field itself
 *   is not separately tracked.
 */

#include <stdlib.h>
#include <string.h>

struct dynhds_entry {
    char *name;
    size_t namelen;
    char *value;
    size_t valuelen;
};

/* Sub-buffer-alias shape: e->name aliases into e itself. */
struct dynhds_entry *entry_new(const char *name, size_t namelen,
                               const char *value, size_t valuelen) {
    struct dynhds_entry *e;
    char *p;

    e = calloc(1, sizeof(*e) + namelen + valuelen + 2);
    if (!e)
        return NULL;
    e->name = p = (char *)e + sizeof(*e);
    memcpy(p, name, namelen);
    e->namelen = namelen;
    e->value = p += namelen + 1;
    memcpy(p, value, valuelen);
    e->valuelen = valuelen;
    return e;  /* caller frees the whole entry, sub-buffers go with it */
}

struct mem {
    char *buf;
    size_t len;
};

/* Local-into-field ownership transfer shape: ptr is local, then handed
 * to mem->buf.  After the assignment, *mem owns the buffer; foo()
 * returns *mem to the caller. */
struct mem *foo(struct mem *m, size_t n) {
    char *ptr = malloc(n);
    m->buf = ptr;       /* ownership now lives in *m, not in `ptr` */
    m->len = n;
    return m;
}
