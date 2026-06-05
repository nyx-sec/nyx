// Phase 11 (Track J.9) — Go DATA_EXFIL benign control fixture.
package benign

import (
    "net/http"
    "net/url"
)

var allowlist = map[string]struct{}{"127.0.0.1": {}, "localhost": {}}

func Run(host string) {
    if _, ok := allowlist[host]; !ok {
        return
    }
    secret := "alice-creds"
    q := url.Values{"token": {secret}}
    u := url.URL{Scheme: "http", Host: host, Path: "/exfil", RawQuery: q.Encode()}
    _, _ = http.Get(u.String())
}
