package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.GET("/users", listUsers)
	r.Run()
}

func listUsers(c *gin.Context) {
	c.JSON(200, []string{})
}
