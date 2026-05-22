// Rust JSON_PARSE depth-bomb vuln fixture.
//
// Models a config-driven JSON ingest endpoint that picks the parser
// input based on the request payload tag - `*_DEEP` routes through a
// 100-level nested array literal that drives `serde_json::from_str`
// past the 64-level depth budget; `*_SHALLOW` routes through a flat
// `[]` parse that leaves the predicate clear.  This shape is needed
// by the differential runner: the vuln-payload attempt and the
// benign-control attempt both load the same fixture, and only the
// payload-routed deep branch trips the `JsonParseExcessiveDepth`
// predicate.
//
// `serde_json` defaults to a recursion limit of 128 stack frames
// during `from_str`, so the nesting is capped at 100 to stay under
// the parser's own guard while still overshooting the predicate's
// 64-level budget.  The harness walks the returned `Value`
// iteratively to compute the observed depth and emits a
// `ProbeKind::JsonParse` record.

pub fn run(value: &str) -> serde_json::Value {
    if value.contains("DEEP") {
        let depth = 100usize;
        let mut nested = String::with_capacity(depth * 2);
        for _ in 0..depth {
            nested.push('[');
        }
        for _ in 0..depth {
            nested.push(']');
        }
        serde_json::from_str(&nested).unwrap_or(serde_json::Value::Null)
    } else {
        serde_json::from_str("[]").unwrap_or(serde_json::Value::Null)
    }
}
