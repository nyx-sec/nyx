#include <stdlib.h>
#include <stdio.h>

/* Program-lifetime handles kept in file-scope variables, released in a
   separate shutdown function.  Expected: no resource findings. */

static char *g_buf;
static FILE *g_log;

void init(void) {
    g_buf = malloc(100);
    g_log = fopen("/var/log/app.log", "a");
}

void adopt(void) {
    char *local = malloc(10);
    g_buf = local;
}

void shutdown_all(void) {
    free(g_buf);
    if (g_log) fclose(g_log);
}

/* A function-scope static keeps the handle for the whole program. */
void append_line(const char *s) {
    static FILE *log;
    if (!log)
        log = fopen("/var/log/app.log", "a");
    fputs(s, log);
}
