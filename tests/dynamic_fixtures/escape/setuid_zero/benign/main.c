/*
 * Phase 20 (Track E.5) — benign counterpart for setuid_zero.
 */

#include <stdio.h>

int main(void) {
    printf("__NYX_SINK_HIT__\n");
    printf("benign:setuid_zero\n");
    printf("__NYX_PROBE_DONE__\n");
    return 0;
}
