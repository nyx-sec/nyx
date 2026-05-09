// Phase 16 fixture: gin handler.  The `*gin.Context` parameter type
// marks `Handler` as a `GinRoute` entry point.  The seeding policy
// paints `c` as `Source(Cap::all())`; the receiver-method call
// `c.Query("name")` propagates the receiver taint forward, so the
// returned `name` is tainted and flowing into `db.Query` fires the
// SQL_QUERY sink.
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
