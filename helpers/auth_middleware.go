package helpers

import (
	"context"
	"errors"
	"go-auth-service/models"
	"go-auth-service/utils"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type contextKey string

const authClaimsKey contextKey = "authClaims"

// AuthMiddleware validates the access token and ensures it's an active session.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			utils.WriteResponse(w, "Missing or invalid Authorization header")
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := ValidateJWT(tokenStr)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			utils.WriteResponse(w, "Invalid or expired token")
			return
		}

		authSessionCollection := utils.GetDatabaseCollection("auth-session")
		ctx, cancel := utils.GetDatabaseContext()
		defer cancel()

		var session models.AuthSession
		sessionErr := authSessionCollection.FindOne(ctx, bson.D{
			{"connections", bson.D{
				{"$elemMatch", bson.D{
					{"token", tokenStr},
				}},
			}},
		}).Decode(&session)

		if errors.Is(sessionErr, mongo.ErrNoDocuments) {
			w.WriteHeader(http.StatusUnauthorized)
			utils.WriteResponse(w, "Session expired or logged out")
			return
		}
		if sessionErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			utils.WriteResponse(w, "Internal server error")
			return
		}

		ctxWithClaims := context.WithValue(r.Context(), authClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctxWithClaims))
	})
}

func GetAuthClaims(r *http.Request) (jwt.MapClaims, bool) {
	v := r.Context().Value(authClaimsKey)
	claims, ok := v.(jwt.MapClaims)
	return claims, ok
}
