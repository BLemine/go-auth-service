package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func WriteResponse(w http.ResponseWriter, message string) {
	_, err := w.Write([]byte(message))
	if err != nil {
		fmt.Println("Oops got an error at request handling", err)
		return
	}
}

// StartApp initializes the application server and begins listening on the specified address with the provided router.
func StartApp(address string, router *chi.Mux) error {
	return http.ListenAndServe(address, router)
}

func GetHashedData(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	hashed := hash.Sum(nil)
	return hex.EncodeToString(hashed)
}

func GetElementObjectId(elementId string) (bson.ObjectID, error) {
	return bson.ObjectIDFromHex(elementId)
}

func ToObjectIDs(ids []string) ([]bson.ObjectID, error) {
	oids := make([]bson.ObjectID, 0, len(ids))
	for _, s := range ids {
		oid, err := bson.ObjectIDFromHex(s)
		if err != nil {
			return nil, err
		}
		oids = append(oids, oid)
	}
	return oids, nil
}

func DecodeJSONRequest[T any](r *http.Request, dst *T) error {
	if err := json.NewDecoder(r.Body).Decode(&dst); err != nil {
		return err
	}
	return nil
}
