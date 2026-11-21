// Recall guard for `go_non_request_accessors_clean.go`: `c.Param` on a
// `*gin.Context` is request input, so the delete by that id fires.  Pinned in
// `auth_analysis_tests`.
package posts

import (
	"github.com/gin-gonic/gin"

	"example.com/store"
)

func deletePost(c *gin.Context) {
	postID := c.Param("id")
	store.DB.DeletePost(postID)
	c.JSON(200, nil)
}

func removePost(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := q.Get("id")
	store.DB.DeletePost(id)
}
