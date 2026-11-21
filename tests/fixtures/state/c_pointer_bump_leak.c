#include <stdlib.h>
#include <stdio.h>

/* Bumping the pointer with `+=` does not hand the allocation off: the
 * buffer is still owned here and is never freed. */
void bump_and_forget(void) {
    char *cursor = malloc(16);
    cursor += 1;
    putchar(*cursor);
}
