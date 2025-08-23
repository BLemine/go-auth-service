package routers

import (
	"errors"
	"go-auth-service/helpers"
	"go-auth-service/models"
	"go-auth-service/utils"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func getToken(w http.ResponseWriter, r *http.Request) {
	// Parse the request body
	var loginReq models.LoginRequest
	requestErr := utils.DecodeJSONRequest(r, &loginReq)
	if requestErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, models.BaseResponse{
			Code:    001,
			Message: "Invalid request body",
		})
		return
	}

	// Validate required fields
	if loginReq.Username == "" || loginReq.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, models.BaseResponse{
			Code:    001,
			Message: "Username and password are required",
		})
		return
	}

	// Get database connection
	usersCollection := utils.GetDatabaseCollection("users")
	ctx, cancel := utils.GetDatabaseContext()
	defer cancel()

	// Check the user existence
	var user models.User
	err := usersCollection.FindOne(ctx, bson.D{
		{"username", loginReq.Username},
		{"password", utils.GetHashedData(loginReq.Password)},
		{"status", bson.M{"$ne": "ARCHIVED"}},
	}).Decode(&user)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "application/json")
			render.JSON(w, r, models.BaseResponse{
				Code:    001,
				Message: "Invalid credentials",
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		log.Println("Oops couldn't find the user::: ", err)
		return
	}

	// --------

	// Building the jwt token, refresh-token
	tokenStr, refreshTokenStr, tokenExpirationInMinutes, refreshTokenExpirationInHours, tokenErr := helpers.GetAccessToken(user)
	if tokenErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.JSON(w, r, models.BaseResponse{
			Code: 001, Message: "Internal server error",
		})
		log.Println("Oops couldn't generate the token::: ", tokenErr)
		return
	}

	// persist the user's session
	sessionPersistenceErr := helpers.PersistAuthSession(tokenStr, refreshTokenStr, tokenExpirationInMinutes, user.Email)
	if sessionPersistenceErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.JSON(w, r, models.BaseResponse{
			Code:    001,
			Message: "Internal server error",
		})
		log.Println("Oops couldn't persist the session::: ", sessionPersistenceErr)
		return
	}

	// build response
	loginResponse := models.LoginResponse{
		Token:                  tokenStr,
		RefreshToken:           refreshTokenStr,
		TokenExpiration:        tokenExpirationInMinutes,
		RefreshTokenExpiration: refreshTokenExpirationInHours,
	}

	render.JSON(w, r, loginResponse)
}

func refreshToken(w http.ResponseWriter, r *http.Request) {
	authSessionCollection := utils.GetDatabaseCollection("auth-session")
	ctx, cancel := utils.GetDatabaseContext()
	defer cancel()

	var refreshTokenRequest models.RefreshTokenRequest
	requestErr := utils.DecodeJSONRequest(r, &refreshTokenRequest)
	if requestErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, models.BaseResponse{
			Code:    001,
			Message: "Invalid request body",
		})
		return
	}

	filter := bson.D{
		{"connections", bson.D{
			{"$elemMatch", bson.D{
				{"refreshToken", refreshTokenRequest.RefreshToken},
			}},
		}},
	}

	var retrievedSession models.AuthSession
	authSessionRetrievalErr := authSessionCollection.FindOne(ctx, filter).Decode(&retrievedSession)
	if errors.Is(authSessionRetrievalErr, mongo.ErrNoDocuments) {
		w.WriteHeader(http.StatusUnauthorized)
		render.JSON(w, r, models.BaseResponse{
			Code: 1, Message: "Unknown or expired refresh-token",
		})
		return
	} else if authSessionRetrievalErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.JSON(w, r, models.BaseResponse{
			Code: 1, Message: "Internal server error",
		})
		return
	}

	// retrieve the user
	usersCollection := utils.GetDatabaseCollection("users")
	userCtx, userCancel := utils.GetDatabaseContext()
	defer userCancel()

	var user models.User
	userSelectionErr := usersCollection.FindOne(userCtx, bson.D{
		{"email", retrievedSession.UserEmail},
		{"status", bson.M{"$ne": "ARCHIVED"}},
	}).Decode(&user)

	if userSelectionErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.JSON(w, r, models.BaseResponse{
			Code: 1, Message: "Couldn't find the user attached to this refresh-token",
		})
		log.Println("Oops couldn't find the user attached to this refresh-token ::: ", userSelectionErr)
		return
	}

	tokenStr, refreshTokenStr, tokenExpirationInMinutes, refreshTokenExpirationInHours, tokenErr := helpers.GetAccessToken(user)

	if tokenErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.JSON(w, r, models.BaseResponse{
			Code: 1, Message: "Couldn't generate a new token",
		})
		log.Println("Oops couldn't generate the token::: ", tokenErr)
		return
	}

	// build response
	loginResponse := models.LoginResponse{
		Token:                  tokenStr,
		RefreshToken:           refreshTokenStr,
		TokenExpiration:        tokenExpirationInMinutes,
		RefreshTokenExpiration: refreshTokenExpirationInHours,
	}

	render.JSON(w, r, loginResponse)
}

func logout(w http.ResponseWriter, r *http.Request) {}

/*
@body

	firstname,
	lastname,
	email
*/
func sendSignUpEmailOtp(w http.ResponseWriter, r *http.Request) {
	var emailValidationRequest models.SignUpEmailValidation
	requestErr := utils.DecodeJSONRequest(r, &emailValidationRequest)
	if requestErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Invalid request body")
	}
	// Check if the email already exists
	usersCollection := utils.GetDatabaseCollection("users")
	ctx, cancel := utils.GetDatabaseContext()
	defer cancel()

	count, err := usersCollection.CountDocuments(ctx, bson.D{
		{"email", emailValidationRequest.Email},
		{"firstName", emailValidationRequest.Firstname},
		{"lastName", emailValidationRequest.Lastname},
		{"status", bson.M{"$ne": "DRAFT"}},
	})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		log.Println("Oops couldn't find the user::: ", err)
		return
	}

	if count > 0 {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Email already exists")
		return
	}

	draftedUserCount, err := usersCollection.CountDocuments(ctx, bson.D{
		{"email", emailValidationRequest.Email},
		{"status", "DRAFT"},
	})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		log.Println("Oops couldn't find the user::: ", err)
		return
	}

	// Create a draft user if not found
	if draftedUserCount == 0 {
		insertedUser, insertionErr := usersCollection.InsertOne(ctx, bson.D{
			{"email", emailValidationRequest.Email},
			{"username", emailValidationRequest.Email},
			{"password", "<PASSWORD>"},
			{"status", "DRAFT"},
		})

		if insertionErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			utils.WriteResponse(w, "Internal server error")
			log.Println("Oops couldn't insert the user::: ", err)
			return
		}

		log.Println("Inserted user id :: ", insertedUser.InsertedID)
	} else {
		// DO nothing
	}

	// Email OTP handling
	helpers.HandleOtpCreation(w, r, emailValidationRequest.Email, "SIGN_UP")

}

/*
@body

	code,
	email
*/
func confirmSignUpOtp(w http.ResponseWriter, r *http.Request) {
	var emailOtpConfirmationRequest models.SignUpEmailOtpConfirmation
	requestErr := utils.DecodeJSONRequest(r, &emailOtpConfirmationRequest)
	if requestErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Invalid request body")
		return
	}

	otpCollection := utils.GetDatabaseCollection("otp")
	otpCtx, otpCancel := utils.GetDatabaseContext()
	defer otpCancel()

	var existingOtp models.OTP
	otpSelectionErr := otpCollection.FindOne(otpCtx, bson.D{
		{"operationType", "SIGN_UP"},
		{"code", emailOtpConfirmationRequest.Code},
		{"userEmail", emailOtpConfirmationRequest.Email},
	}).Decode(&existingOtp)

	if otpSelectionErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		log.Println("Oops an error occurred during finding otp ::: ", otpSelectionErr)
		return
	}

	// check attempts
	hasExceededAttemptCount, blockedTime, updatingOtpErr := helpers.OtpChecker(existingOtp)
	if updatingOtpErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		log.Println("Oops couldn't update the otp::: ", updatingOtpErr)
		return
	} else if hasExceededAttemptCount {
		w.WriteHeader(http.StatusBadRequest)
		message := "You've exceeded the limit of attempts. Please try again after " + strconv.Itoa(blockedTime) + " minutes"
		utils.WriteResponse(w, message)
		return
	}

	var otpNotFound = existingOtp.Id == bson.NilObjectID
	if otpNotFound {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Invalid OTP")
		return
	} else {
		// update the otp
		otpCollection.FindOneAndUpdate(otpCtx, bson.D{
			{"_id", existingOtp.Id},
		}, bson.D{
			{"$set", bson.D{
				{"isEmailVerified", true},
			}},
		})

		w.WriteHeader(http.StatusOK)
		utils.WriteResponse(w, "OTP confirmed successfully")
		return
	}
}

/*
@body

	email,
	password,
	passwordConfirmation
*/
func addSignUpPersonalDetails(w http.ResponseWriter, r *http.Request) {
	var signUpPersonalDetailsRequest models.SignUpPersonalDetailsRequest
	requestErr := utils.DecodeJSONRequest(r, &signUpPersonalDetailsRequest)
	if requestErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Invalid request body")
		return
	}

	usersCollection := utils.GetDatabaseCollection("users")
	ctx, cancel := utils.GetDatabaseContext()
	defer cancel()

	var user models.User
	userSelectionErr := usersCollection.FindOne(ctx, bson.D{
		{"email", signUpPersonalDetailsRequest.Email},
		{"status", "DRAFT"},
	}).Decode(&user)

	if userSelectionErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		log.Println("Oops couldn't find the user::: ", userSelectionErr)
		return
	}

	if user.Id == bson.NilObjectID {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "User with this email doesn't exist")
		return
	}

	if !user.IsEmailVerified {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Email is not verified")
		return
	}

	userUpdateErr := usersCollection.FindOneAndUpdate(ctx, bson.D{
		{"_id", user.Id},
	}, bson.M{
		"status":   "CONFIRMED",
		"password": signUpPersonalDetailsRequest.Password,
	})

	if userUpdateErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		log.Println("Oops couldn't update the user::: ", userUpdateErr)
		return
	}
	// TODO: send mail to user
	render.JSON(w, r, "User added successfully")

}

func AuthRouter(r chi.Router) {
	r.Post("/signIn", getToken)
	r.Post("/refreshToken", refreshToken)
	r.Post("/logout", logout)
	// email validation -> otp confirmation -> firstname, lastname, password, password confirmation -> success screen
	// then the user can do an upgrade inside the app
	r.Post("/signUp/email", sendSignUpEmailOtp)
	r.Post("/signUp/otp", confirmSignUpOtp)
	r.Post("/signUp/personal-details", addSignUpPersonalDetails)
}
