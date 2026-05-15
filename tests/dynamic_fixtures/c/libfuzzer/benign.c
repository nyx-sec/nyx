/* Phase 16 — libFuzzer entry, benign. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)data; (void)size;
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);
    system("echo hello");
    return 0;
}
