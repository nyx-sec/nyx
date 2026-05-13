// Fixture: spec derived via FromFuncSummaryWalk (FuncSummary records
// `tainted_sink_params` for a param that flows to a sink, without an
// in-evidence flow_steps trace).

fn read_path(_root: &str, name: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(name)
}

fn main() {
    let _ = read_path("/", "/etc/passwd");
}
