#include <stdlib.h>
#include <string.h>

/* Each allocation is handed to the caller through a pointer parameter.
   Expected: no resource findings. */

struct buf { char *data; size_t len; };

int buf_new(size_t n, struct buf **out) {
    struct buf *b = calloc(1, sizeof(*b));
    if (!b)
        return -1;
    b->len = n;
    *out = b;
    return 0;
}

int dup_it(const char *s, char **out) {
    size_t n = strlen(s) + 1;
    char *p = malloc(n);
    if (!p)
        return -1;
    memcpy(p, s, n);
    *out = p;
    return 0;
}

struct node { char *data; struct node *next; };

void push(struct node **head) {
    struct node *n = malloc(sizeof(*n));
    if (n == NULL) return;
    n->next = *head;
    *head = n;
}
