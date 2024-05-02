package resolv

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/syslab-wm/mu"
)

func GetMongoDBConnectionString() string {
	if err := godotenv.Load(); err != nil {
		mu.Fatalf("No .env file found")
	}

	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		mu.Fatalf("You must set your 'MONGODB_URI' environment variable.")
	}

	return uri
}
