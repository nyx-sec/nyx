/* Phase 16 — free function with (const char *, size_t), benign. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

void run(const char *payload, size_t len) {
    (void)payload; (void)len;
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);
    system("echo hello");
}
