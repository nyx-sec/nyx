// Phase 09 (Track J.7) — Go OPEN_REDIRECT benign control fixture.
//
// The handler ignores the attacker-supplied value and redirects to a
// same-origin path; the captured `Location:` header carries no
// off-origin authority.
package vuln

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Run(c *gin.Context, value string) {
	c.Redirect(http.StatusFound, "/dashboard")
}
