package main

import (
	"go-auth-service/routers"
	"go-auth-service/utils"
	"log"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	_ "go-auth-service/docs"
)

// @title Go Auth Service
// @version 1.0
// @description Authentication microservice with JWT, refresh tokens, registration, and password reset flows.
// @BasePath /auth
// @schemes http https
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	// Load config
	configLoadErr := godotenv.Load()
	if configLoadErr != nil {
		log.Printf("Warning: Error loading .env file: %v\n", configLoadErr)
	}
	//
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Route("/auth", routers.AuthRouter)
	r.Get("/swagger/*", httpSwagger.WrapHandler)

	err := utils.StartApp(":8080", r)
	if err != nil {
		log.Fatal("Oops couldn't start the server", err)
		return
	}

}
