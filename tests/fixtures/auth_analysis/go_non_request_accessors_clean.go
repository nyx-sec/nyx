// `Get`, `Query` and `Param` are request input only on the request or a
// framework context.  Here they are a cache lookup, a response header and an
// xorm query, so the helper has no user-input evidence and its id-shaped
// arguments are not scoped identifiers.  Pinned in `auth_analysis_tests`.
package store

import "example.com/models/repo_model"

type Cache struct{}

func (c *Cache) Get(key string) string { return "" }

type Repo struct{ ID int64 }

func LoadRepo(cache *Cache, repos []Repo) {
	v := cache.Get("k")
	_ = v
	repo_model.GetRepositoryByID(repos[0].ID)
}

func Sync(db *xorm.Engine, resp *http.Response, ids []int64) {
	etag := resp.Header.Get("ETag")
	rows, _ := db.Query("select 1")
	_, _ = etag, rows
	store.DeleteByID(ids[0])
}
