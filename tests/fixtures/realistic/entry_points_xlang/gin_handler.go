// Gin handler.  The `*gin.Context` parameter type marks `Handler`
// as a `GinRoute` entry point.  Seeding policy: the bare `c`
// object is NOT painted as `Source` (would FP on excluded
// lifecycle calls like `c.Set` / `c.Next`).  Adversary bytes
// surface via the access-path label rules at
// `src/labels/go.rs`: `c.Query`, `c.Param`, `c.PostForm`,
// `c.QueryArray`, `c.PostFormArray` are gated on
// `DetectedFramework::Gin` and classify as `Source(Cap::all())`.
// `name := c.Query("name")` produces a tainted local, and
// `db.Query` matches the SQL_QUERY sink list, so the flow
// fires `taint-unsanitised-flow` with `c.Query` as the source.
package handlers

import (
	"database/sql"

	"github.com/gin-gonic/gin"
)

var db *sql.DB

func Handler(c *gin.Context) {
	name := c.Query("name")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
