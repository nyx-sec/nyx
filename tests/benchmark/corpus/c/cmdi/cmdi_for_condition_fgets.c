/* `fgets` in a three-clause `for` condition fills `buf` from stdin. */
#include <stdio.h>
#include <stdlib.h>

void run_lines(void) {
    char buf[256];
    for (; fgets(buf, sizeof(buf), stdin); ) {
        system(buf);
    }
}
