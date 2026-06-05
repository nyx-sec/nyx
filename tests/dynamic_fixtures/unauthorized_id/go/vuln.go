// Phase 11 (Track J.9) — Go UNAUTHORIZED_ID vuln fixture.
package vuln

const callerID = "alice"

var store = map[string]string{"alice": "alice@x", "bob": "bob@x"}

func Run(ownerID string) string {
    return store[ownerID]
}
