/*
 * Phase 20 (Track E.5) — benign counterpart for chmod_4755 fixture.
 *
 * Same sink probe, but no escape attempt.  Used by the test as a sanity
 * check that the harness boots, reaches the sink, and prints the marker
 * under the same Strict-profile options that the vuln fixture runs with.
 * If the benign run fails to emit `__NYX_SINK_HIT__`, the test fails as a
 * Track-B regression — the harness contract is broken before any
 * containment claim can be made.
 */

#include <stdio.h>

int main(void) {
    printf("__NYX_SINK_HIT__\n");
    printf("benign:chmod_4755\n");
    printf("__NYX_PROBE_DONE__\n");
    return 0;
}
