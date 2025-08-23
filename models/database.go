package models

import (
	"go.mongodb.org/mongo-driver/v2/bson"
)

type User struct {
	Id              bson.ObjectID `json:"id" bson:"_id,omitempty"`
	Firstname       string        `json:"firstname" bson:"firstname"`
	Lastname        string        `json:"lastname" bson:"lastname" `
	Email           string        `json:"email" bson:"email"`
	Username        string        `json:"username" bson:"username"`
	Password        string        `json:"password" bson:"password"`
	Status          string        `json:"status" bson:"status"` // DRAFT, CONFIRMED, SUSPENDED
	Roles           []string      `json:"roles" bson:"roles"`   // ADMIN, USER
	IsEmailVerified bool          `json:"isEmailVerified" bson:"isEmailVerified"`
}

type UserSession struct {
	Id           string        `json:"id"`
	Token        string        `json:"token"`
	RefreshToken string        `json:"refreshToken"`
	Expiration   int           `json:"expiration"`
	CreationDate bson.DateTime `json:"creationDate"`
}

type AuthSession struct {
	Id          string        `json:"id"`
	UserEmail   string        `json:"userEmail"`
	Connections []UserSession `json:"connections"`
}

type OTP struct {
	Id            bson.ObjectID `json:"id" bson:"_id,omitempty"`
	UserEmail     string        `json:"userEmail" bson:"userEmail"`
	UserId        string        `json:"userId" bson:"userId"`
	AttemptCount  int           `json:"attemptCount" bson:"attemptCount"`
	Code          string        `json:"code" bson:"code"`
	IsVerified    bool          `json:"isVerified" bson:"isVerified"`
	CreationDate  bson.DateTime `json:"creationDate" bson:"creationDate"`
	OperationType string        `json:"operationType" bson:"operationType"` // SIGN_UP, FORGOT_PASSWORD.
}
