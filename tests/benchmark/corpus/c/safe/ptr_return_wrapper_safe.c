#include <stdio.h>
#include <stdlib.h>

/* Pointer-returning wrappers whose command argument is a constant: the
   tainted parameter never reaches a shell sink. */
static FILE *open_listing(char *unused) {
    (void)unused;
    return fopen("/var/log/app.log", "r");
}

static char *run_date(char *label) {
    system("date");
    return label;
}

void from_env(void) {
    char *label = getenv("LABEL");
    open_listing(label);
    run_date(label);
}
