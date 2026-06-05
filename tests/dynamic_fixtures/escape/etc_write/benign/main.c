/*
 * Phase 20 (Track E.5) — benign counterpart for etc_write fixture.
 */

#include <stdio.h>

int main(void) {
    printf("__NYX_SINK_HIT__\n");
    printf("benign:etc_write\n");
    printf("__NYX_PROBE_DONE__\n");
    return 0;
}
