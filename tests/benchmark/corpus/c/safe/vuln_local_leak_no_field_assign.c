/*
 * c-vuln-realrepo-001 — vulnerable counterpart to
 * safe_struct_field_subbuffer_alloc.c.  Confirms the field-LHS gate in
 * apply_assignment did NOT over-suppress: a plain local-to-local
 * assignment (no field on the LHS) must still flag the leak when the
 * resource never reaches a release call or out-parameter.
 *
 * Pattern: malloc → local alias copy → no free, no return.
 */

#include <stdlib.h>
#include <string.h>

void leaky_helper(size_t n) {
    char *buf = malloc(n);
    if (!buf)
        return;
    char *cursor = buf;          /* alias copy — both still local handles */
    memset(cursor, 0, n);
    /* deliberately no free(buf) and no out-param transfer — leak */
}
