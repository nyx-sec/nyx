// Phase 10 (Track D.3) stub-end-to-end fixture: Go + HTTP.
//
// Body-only fragment, not a standalone `go run`-able program.  The
// companion test in `tests/stubs_e2e_per_lang.rs` wraps these lines
// in `package main` + the union of stdlib imports required by both
// the spliced probe shim and this fragment, places the Go probe
// shim ahead of `func main`, and then invokes `go run` on the
// resulting file.
//
// The verifier publishes:
//
//   NYX_HTTP_ENDPOINT — http://127.0.0.1:{port} the HttpStub listens on.
//   NYX_HTTP_LOG      — companion log path the harness appends attempted
//                       outbound calls to so the host HttpStub picks
//                       them up on drain_events() even when the request
//                       bypasses the on-the-wire listener (DNS-mocked,
//                       network-isolated sandbox, pre-flight check).
//
// This fragment records an attempted SSRF call to
// http://169.254.169.254/latest/meta-data/ through the Go shim helper
// __nyx_stub_http_record without issuing the actual network call.
method := "GET"
url := "http://169.254.169.254/latest/meta-data/"
body := ""
__nyx_stub_http_record(method, url, body, map[string]string{"driver": "net/http"})
// Echo so the host can confirm the driver ran end-to-end.
fmt.Print(os.Getenv("NYX_HTTP_ENDPOINT"))
