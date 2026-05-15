/*
 * Phase 20 (Track E.5) — benign counterpart for raw_socket_bind.
 */

#include <stdio.h>

int main(void) {
    printf("__NYX_SINK_HIT__\n");
    printf("benign:raw_socket_bind\n");
    printf("__NYX_PROBE_DONE__\n");
    return 0;
}
