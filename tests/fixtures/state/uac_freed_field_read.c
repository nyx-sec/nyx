#include <stdlib.h>
#include <string.h>

struct node { char name[32]; };

/* Reading a field through a freed pointer is a use after free. */
void copy_name(char *buf) {
    struct node *n = malloc(sizeof(struct node));
    free(n);
    strcpy(buf, n->name);
}
