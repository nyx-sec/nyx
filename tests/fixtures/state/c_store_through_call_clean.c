#include <stdlib.h>

struct item { int a; };
struct slist { void *util; };
struct slist *string_list_append(struct slist *l, const char *s);
struct item **slab_at(int c);
void *xcalloc(size_t a, size_t b);
void *xmalloc(size_t n);

void member_of_call_result(struct slist *files, const char *name) {
    struct item *item = xcalloc(1, sizeof(*item));
    string_list_append(files, name)->util = item;
}

void deref_of_call_result(int c) {
    struct item *name;
    name = *slab_at(c);
    if (!name) {
        name = xmalloc(sizeof(*name));
        *slab_at(c) = name;
    }
    name->a = 1;
}
