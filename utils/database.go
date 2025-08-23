package utils

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var (
	client *mongo.Client
	once   sync.Once
)

// InitDB initializes the MongoDB connection
func InitDB() error {
	var err error
	once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		databaseUrl := os.Getenv("DATABASE_URI")
		opts := options.Client().ApplyURI(databaseUrl)
		client, err = mongo.Connect(opts)
		if err != nil {
			log.Printf("Failed to connect to MongoDB: %v", err)
			return
		}

		// Verify the connection - v2 Ping only takes context
		err = client.Ping(ctx, nil)
		if err != nil {
			log.Printf("Failed to ping MongoDB: %v", err)
			return
		}

		log.Println("Successfully connected to MongoDB")
	})
	return err
}

func GetDatabaseCollection(collectionName string) (db *mongo.Collection) {
	if client == nil {
		if err := InitDB(); err != nil {
			log.Printf("Failed to initialize database: %v", err)
			return nil
		}
	}
	databaseName := os.Getenv("DATABASE_NAME")
	return client.Database(databaseName).Collection(collectionName)
}

func GetDatabaseContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}
