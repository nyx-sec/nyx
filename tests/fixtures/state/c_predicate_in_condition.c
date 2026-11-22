#include <stdio.h>
#include <stdlib.h>

int should_close(FILE *f);
int is_free(char *p);
void use(char *p);

/* A predicate named like a release is not a release. */
void predicate_then_close(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    if (should_close(f)) {
        fclose(f);
        return;
    }
    fclose(f);
}

void free_predicate(void) {
    char *p = malloc(10);
    if (!p)
        return;
    if (is_free(p)) {
        free(p);
        return;
    }
    use(p);
    free(p);
}

/* A real close in the condition followed by another close is still a double close. */
void double_close_in_cond(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    if (fclose(f))
        return;
    fclose(f);
}
