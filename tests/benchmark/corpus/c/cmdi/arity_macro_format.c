#include <stdio.h>
#include <stdlib.h>

/* Project wrapper macro: tree-sitter sees the unexpanded name only. */
#define SNPRINTF2(str, len, fmt, a, b) snprintf((str), (len), (fmt), (a), (b))

void build_and_run(char *a, char *b) {
    char cmd[256];
    char *tmpl = getenv("CLOSE_TEMPLATE");
    if (tmpl == NULL)
        return;
    SNPRINTF2(cmd, sizeof(cmd), tmpl, a, b);
    system(cmd);
}
