package main

import (
	"go-auth-service/routers"
	"go-auth-service/utils"
	"log"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

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

	err := utils.StartApp(":8080", r)
	if err != nil {
		log.Fatal("Oops couldn't start the server", err)
		return
	}

}
