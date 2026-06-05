/* Phase 16 — free function with (const char *, size_t), vulnerable.
 *
 * Cap: CODE_EXEC. Concatenates payload into a shell command.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run(const char *payload, size_t len) {
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);
    if (!payload || len > 2048) return;
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "echo hello %s", payload);
    system(cmd);
}
