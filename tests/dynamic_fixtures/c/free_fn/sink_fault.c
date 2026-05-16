/* Phase 08 (a) acceptance fixture — crash at the sink.
 *
 * Cap: FMT_STRING.  Prints the `__NYX_SINK_HIT__` sentinel so the runner
 * sees the in-harness sink-hit, then NULL-dereferences when handed the
 * vuln payload.  The harness's `__nyx_install_crash_guard` was installed
 * earlier in `main`, so SIGSEGV writes a Crash probe to `NYX_PROBE_PATH`,
 * which lifts the `Oracle::SinkCrash` predicate to `Confirmed`.
 *
 * Differential confirmation: the paired benign payload carries the
 * `NYX_BENIGN` marker.  The short-circuit below returns cleanly on the
 * benign run so `benign_fired = false`, satisfying the §4.1 rule. */
#include <stddef.h>
#include <stdio.h>
#include <string.h>

void run(const char *payload, size_t len) {
    (void)len;
    printf("__NYX_SINK_HIT__\n");
    fflush(stdout);
    if (payload && strstr(payload, "NYX_BENIGN")) {
        return;
    }
    volatile char *p = NULL;
    *p = 1;
}
