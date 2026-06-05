// Phase 09 (Track J.7) — Go OPEN_REDIRECT vuln fixture.
//
// The gin handler splices `value` straight into
// `gin.Context.Redirect` without host validation; an attacker URL
// routes the captured `Location:` header off-origin.
package vuln

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Run(c *gin.Context, value string) {
	c.Redirect(http.StatusFound, value)
}
