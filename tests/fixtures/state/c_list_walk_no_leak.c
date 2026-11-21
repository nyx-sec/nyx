#include <stdlib.h>

struct node {
    struct node *next;
};

/* The walker aliases the head and the list is returned to the caller, so
 * nothing leaks. */
struct node *list_create(int n) {
    struct node *head = calloc(1, sizeof(struct node));
    struct node *cur = head;
    while (--n) {
        cur->next = calloc(1, sizeof(struct node));
        cur = cur->next;
    }
    return head;
}
