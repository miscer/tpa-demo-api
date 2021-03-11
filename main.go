package main

import (
	"tpa-api/handlers"

	"github.com/gin-contrib/cors"
	"github.com/kelseyhightower/envconfig"

	"github.com/gin-gonic/gin"
)

func main() {
	var c handlers.Config
	envconfig.MustProcess("", &c)

	h := handlers.Handlers{Config: c}

	r := gin.Default()
	r.Use(cors.Default())
	r.POST("/auth/:provider", h.GetAuthURL)
	r.POST("/auth/:provider/finish", h.CompleteAuth)
	r.Run()
}
