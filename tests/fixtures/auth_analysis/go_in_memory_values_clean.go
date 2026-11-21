// Go values that are not data-layer clients: request data accessors, local
// sets and maps, atomics, `url.Values`, stdlib slice helpers and router
// registrations.  Their names or constant keys look id-shaped, and `Get`,
// `Add`, `Remove`, `Load` match the verb vocabulary, but nothing here reads or
// writes a store.  Pinned in `auth_analysis_tests`.
package cmd

import (
	"net/http"
	"net/url"
	"slices"
	"sync/atomic"

	"example.com/container"
	xhttp "example.com/internal/http"
	"example.com/modules/web"
	"example.com/routers/repo"
)

type rootCommand struct {
	configVersionID atomic.Int32
}

func reload(r *rootCommand, req *http.Request) int32 {
	return r.configVersionID.Load()
}

func GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	vid := r.Form.Get(xhttp.VersionID)
	r.Header.Add(xhttp.HeaderRequestID, vid)
	w.Write([]byte(vid))
}

func PossibleUsers(req *http.Request, ids []int64, userID int64) {
	uniqueIDs := container.SetOf(ids...)
	uniqueIDs.Remove(0)
	members := container.SetOf(1, 2)
	members.Remove(userID)
	vals := url.Values{}
	vals.Add("id", "1")
	ids = slices.Delete(ids, 0, 1)
}

func registerWebRoutes(m *web.Router, req *http.Request) {
	m.Get("/blob/{sha}", repo.DownloadByID)
}
