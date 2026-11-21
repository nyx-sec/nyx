package cmd

import (
	"html"
	"net/http"
	"net/url"
	"sync/atomic"

	"example.com/container"
	xhttp "example.com/internal/http"
	"example.com/modules/web"
	"example.com/routers/repo"
)

type rootCommand struct {
	configVersionID atomic.Int32
}

// An atomic field, a local set, url.Values, request header and form
// accessors and a router registration are not data-layer operations.
func reload(r *rootCommand, req *http.Request) int32 {
	return r.configVersionID.Load()
}

func GetObjectHandler(w http.ResponseWriter, r *http.Request) {
	vid := r.Form.Get(xhttp.VersionID)
	r.Header.Add(xhttp.HeaderRequestID, vid)
	w.Write([]byte(html.EscapeString(vid)))
}

func PossibleUsers(req *http.Request, ids []int64, userID int64) {
	uniqueIDs := container.SetOf(ids...)
	uniqueIDs.Remove(0)
	vals := url.Values{}
	vals.Add("id", "1")
}

func registerWebRoutes(m *web.Router, req *http.Request) {
	m.Get("/blob/{sha}", repo.DownloadByID)
}
