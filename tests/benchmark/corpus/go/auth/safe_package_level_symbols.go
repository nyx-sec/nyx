package cmd

import (
	"bytes"
	"net/http"

	"example.com/cfgmgr"
	"example.com/common"
	"example.com/internal/grid"
)

const storageRESTDiskID = "diskID"

// An imported package's constant and a file-level const name declarations,
// not per-request values.
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
