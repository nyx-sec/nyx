/* Phase 08 (b) acceptance fixture — crash outside the sink.
 *
 * Cap: FMT_STRING.  A global constructor (`__attribute__((constructor))`)
 * runs before `main`, so the abort fires BEFORE the harness reaches
 * `__nyx_install_crash_guard`.  No Crash probe is written, the
 * `Oracle::SinkCrash` predicate sees `process_crashed &&
 * !has_sink_crash_probe`, and the verifier routes to
 * `Inconclusive(UnrelatedCrash)` instead of `Confirmed`.
 *
 * The `run` body is unreachable but must compile so the entry symbol
 * resolves at link time. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor)) static void nyx_fixture_crash_in_setup(void) {
    abort();
}

void run(const char *payload, size_t len) {
    (void)payload;
    (void)len;
    printf("__NYX_SINK_HIT__\n");
}
