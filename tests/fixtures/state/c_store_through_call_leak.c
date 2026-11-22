#include <stdlib.h>

struct item { int a; };
void *xcalloc(size_t a, size_t b);

void local_only(int c) {
    struct item *item = xcalloc(1, sizeof(*item));
    item->a = c;
}
