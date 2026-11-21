// A selector rooted at an imported package, and a file-level const, name a
// declaration.  Neither is a per-request value, even though `LDAPUID`,
// `storageRESTDiskID` and `grid.GetByteBuffer` look id-shaped.  Pinned in
// `auth_analysis_tests`.
package cmd

import (
	"bytes"
	"net/http"

	"example.com/cfgmgr"
	"example.com/common"
	"example.com/internal/grid"
)

const storageRESTDiskID = "diskID"

func LoadLDAP(req *http.Request) {
	uid := cfgmgr.Mgr.Get(req.Context(), common.LDAPUID)
	_ = uid
}

func ListenHandler(w http.ResponseWriter, req *http.Request) {
	buf := bytes.NewBuffer(grid.GetByteBuffer()[:0])
	w.Write(buf.Bytes())
}

func DiskHandler(w http.ResponseWriter, r *http.Request) {
	store.Lookup(r, storageRESTDiskID)
}
