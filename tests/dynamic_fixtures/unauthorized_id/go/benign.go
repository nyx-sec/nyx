// Phase 11 (Track J.9) — Go UNAUTHORIZED_ID benign control fixture.
package benign

const callerID = "alice"

var store = map[string]string{"alice": "alice@x", "bob": "bob@x"}

func Run(ownerID string) string {
    if ownerID != callerID {
        return ""
    }
    return store[ownerID]
}
