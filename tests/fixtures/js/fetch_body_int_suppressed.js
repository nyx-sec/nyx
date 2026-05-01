// DATA_EXFIL type-suppression fixture: a Sensitive cookie source coerced
// to an integer via `parseInt(...)` is NOT a credential payload; the
// resulting numeric body cannot encode a session token, header secret, or
// other exfiltratable material.  The type-aware sink suppression in
// `is_type_safe_for_sink` (see `src/ssa/type_facts.rs`) recognises the
// proven-`Int` SSA value at the gate and silences the cap.
//
// Negative regression: without DATA_EXFIL in the type-suppressible mask
// this would over-fire on every `fetch({ body: parseInt(req.cookies.x) })`
// pattern (e.g. analytics ingestion of session counters).
//
// Driven by `fetch_data_exfil_integration_tests.rs`.
function reportSessionCount(req) {
    var count = parseInt(req.cookies.session_count, 10);
    fetch('/metrics', {
        method: 'POST',
        body: count,
    });
}
