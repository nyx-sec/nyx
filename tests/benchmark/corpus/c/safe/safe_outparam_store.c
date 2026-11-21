#include <stdlib.h>
#include <string.h>

struct buf { char *data; size_t len; };

/* The allocation is handed to the caller through `out`. */
int buf_new(size_t n, struct buf **out) {
    struct buf *b = calloc(1, sizeof(*b));
    if (!b)
        return -1;
    b->len = n;
    *out = b;
    return 0;
}
