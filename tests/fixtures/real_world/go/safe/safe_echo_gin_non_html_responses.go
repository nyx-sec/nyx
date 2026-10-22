package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

func echoJSON(c echo.Context) error {
	name := c.QueryParam("name")
	return c.JSON(http.StatusOK, map[string]string{"name": name})
}

func echoString(c echo.Context) error {
	name := c.QueryParam("name")
	return c.String(http.StatusOK, "hello "+name)
}

func ginString(c *gin.Context) {
	name := c.Query("name")
	c.String(http.StatusOK, "hello "+name)
}

func ginTemplate(c *gin.Context) {
	name := c.Query("name")
	c.HTML(http.StatusOK, "index.tmpl", gin.H{"name": name})
}
