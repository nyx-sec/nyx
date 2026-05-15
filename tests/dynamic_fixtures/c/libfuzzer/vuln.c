/* Phase 16 — libFuzzer entry, vulnerable.
 *
 * Real libFuzzer entry: `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.
 * Cap: CODE_EXEC.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);
    if (size == 0 || size > 2048) return 0;
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "echo hello %.*s", (int)size, (const char*)data);
    system(cmd);
    return 0;
}
