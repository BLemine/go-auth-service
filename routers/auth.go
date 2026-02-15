package routers

import (
	"encoding/json"
	"errors"
	"go-auth-service/helpers"
	"go-auth-service/models"
	"go-auth-service/utils"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	if refreshTokenRequest.RefreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, models.BaseResponse{
			Code:    001,
			Message: "Refresh token is required",
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

	if _, err := helpers.ValidateJWT(refreshTokenRequest.RefreshToken); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		render.JSON(w, r, models.BaseResponse{
			Code: 1, Message: "Invalid or expired refresh-token",
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

	_, updateErr := authSessionCollection.UpdateOne(
		ctx,
		bson.D{
			{"userEmail", retrievedSession.UserEmail},
			{"connections", bson.D{
				{"$elemMatch", bson.D{
					{"refreshToken", refreshTokenRequest.RefreshToken},
				}},
			}},
		},
		bson.D{{"$set", bson.D{
			{"connections.$.token", tokenStr},
			{"connections.$.refreshToken", refreshTokenStr},
			{"connections.$.expiration", tokenExpirationInMinutes},
			{"connections.$.creationDate", bson.NewDateTimeFromTime(time.Now())},
		}}},
	)
	if updateErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.JSON(w, r, models.BaseResponse{
			Code: 1, Message: "Internal server error",
		})
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

func logout(w http.ResponseWriter, r *http.Request) {
	var logoutRequest models.LogoutRequest
	decodeErr := json.NewDecoder(r.Body).Decode(&logoutRequest)
	if decodeErr != nil && !errors.Is(decodeErr, io.EOF) {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, models.BaseResponse{
			Code:    001,
			Message: "Invalid request body",
		})
		return
	}

	if logoutRequest.Token == "" && logoutRequest.RefreshToken == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			logoutRequest.Token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if logoutRequest.Token == "" && logoutRequest.RefreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, models.BaseResponse{
			Code:    001,
			Message: "Token or refresh token is required",
		})
		return
	}

	authSessionCollection := utils.GetDatabaseCollection("auth-session")
	ctx, cancel := utils.GetDatabaseContext()
	defer cancel()

	selector := bson.A{}
	if logoutRequest.Token != "" {
		selector = append(selector, bson.D{{"token", logoutRequest.Token}})
	}
	if logoutRequest.RefreshToken != "" {
		selector = append(selector, bson.D{{"refreshToken", logoutRequest.RefreshToken}})
	}

	_, updateErr := authSessionCollection.UpdateOne(
		ctx,
		bson.D{{"connections", bson.D{{"$elemMatch", bson.D{{"$or", selector}}}}}},
		bson.D{{"$pull", bson.D{
			{"connections", bson.D{{"$or", selector}}},
		}}},
	)
	if updateErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.JSON(w, r, models.BaseResponse{
			Code:    001,
			Message: "Internal server error",
		})
		return
	}

	render.JSON(w, r, models.BaseResponse{
		Code:    0,
		Message: "Logged out successfully",
	})
}

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
		return
	}
	if emailValidationRequest.Email == "" || emailValidationRequest.Firstname == "" || emailValidationRequest.Lastname == "" {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Firstname, lastname, and email are required")
		return
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
			{"firstname", emailValidationRequest.Firstname},
			{"lastname", emailValidationRequest.Lastname},
			{"isEmailVerified", false},
		})

		if insertionErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			utils.WriteResponse(w, "Internal server error")
			log.Println("Oops couldn't insert the user::: ", err)
			return
		}

		log.Println("Inserted user id :: ", insertedUser.InsertedID)
	} else {
		_, updateErr := usersCollection.UpdateOne(ctx, bson.D{
			{"email", emailValidationRequest.Email},
			{"status", "DRAFT"},
		}, bson.D{
			{"$set", bson.D{
				{"firstname", emailValidationRequest.Firstname},
				{"lastname", emailValidationRequest.Lastname},
			}},
		})
		if updateErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			utils.WriteResponse(w, "Internal server error")
			log.Println("Oops couldn't update the draft user::: ", updateErr)
			return
		}
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
	if emailOtpConfirmationRequest.Email == "" || emailOtpConfirmationRequest.Code == "" {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Email and code are required")
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

	if errors.Is(otpSelectionErr, mongo.ErrNoDocuments) {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Invalid OTP")
		return
	}
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

	diff := utils.GetDifferenceAbsTwoDatesInMinutes(existingOtp.CreationDate, utils.GetCurrentDateToTime())
	if diff > 5 {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "OTP has expired")
		return
	}

	otpCollection.FindOneAndUpdate(otpCtx, bson.D{
		{"_id", existingOtp.Id},
	}, bson.D{
		{"$set", bson.D{
			{"isVerified", true},
		}},
	})

	usersCollection := utils.GetDatabaseCollection("users")
	userCtx, userCancel := utils.GetDatabaseContext()
	defer userCancel()
	_, userUpdateErr := usersCollection.UpdateOne(userCtx, bson.D{
		{"email", emailOtpConfirmationRequest.Email},
		{"status", "DRAFT"},
	}, bson.D{
		{"$set", bson.D{
			{"isEmailVerified", true},
		}},
	})
	if userUpdateErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		return
	}

	w.WriteHeader(http.StatusOK)
	utils.WriteResponse(w, "OTP confirmed successfully")
	return
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
	if signUpPersonalDetailsRequest.Email == "" || signUpPersonalDetailsRequest.Password == "" || signUpPersonalDetailsRequest.PasswordConfirmation == "" {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Email, password and password confirmation are required")
		return
	}
	if signUpPersonalDetailsRequest.Password != signUpPersonalDetailsRequest.PasswordConfirmation {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Password and confirmation do not match")
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

	otpCollection := utils.GetDatabaseCollection("otp")
	otpCtx, otpCancel := utils.GetDatabaseContext()
	defer otpCancel()
	var verifiedOtp models.OTP
	otpErr := otpCollection.FindOne(otpCtx, bson.D{
		{"userEmail", signUpPersonalDetailsRequest.Email},
		{"operationType", "SIGN_UP"},
		{"isVerified", true},
	}).Decode(&verifiedOtp)
	if errors.Is(otpErr, mongo.ErrNoDocuments) {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "OTP verification required")
		return
	}
	if otpErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		return
	}
	diff := utils.GetDifferenceAbsTwoDatesInMinutes(verifiedOtp.CreationDate, utils.GetCurrentDateToTime())
	if diff > 10 {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "OTP has expired")
		return
	}

	_, userUpdateErr := usersCollection.UpdateOne(ctx, bson.D{
		{"_id", user.Id},
	}, bson.D{
		{"$set", bson.D{
			{"status", "CONFIRMED"},
			{"password", utils.GetHashedData(signUpPersonalDetailsRequest.Password)},
		}},
	})

	if userUpdateErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		log.Println("Oops couldn't update the user::: ", userUpdateErr)
		return
	}

	mailErr := helpers.SendAccountCreationMail(user)
	if mailErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		return
	}

	render.JSON(w, r, "User added successfully")

}

/*
@body

	email
*/
func sendPasswordResetOtp(w http.ResponseWriter, r *http.Request) {
	var resetRequest models.PasswordResetEmailRequest
	requestErr := utils.DecodeJSONRequest(r, &resetRequest)
	if requestErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Invalid request body")
		return
	}
	if resetRequest.Email == "" {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Email is required")
		return
	}

	usersCollection := utils.GetDatabaseCollection("users")
	ctx, cancel := utils.GetDatabaseContext()
	defer cancel()

	var user models.User
	userErr := usersCollection.FindOne(ctx, bson.D{
		{"email", resetRequest.Email},
		{"status", bson.M{"$ne": "ARCHIVED"}},
	}).Decode(&user)
	if errors.Is(userErr, mongo.ErrNoDocuments) {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "User with this email doesn't exist")
		return
	}
	if userErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		return
	}

	helpers.HandleOtpCreation(w, r, resetRequest.Email, "FORGOT_PASSWORD")
}

/*
@body

	code,
	email
*/
func confirmPasswordResetOtp(w http.ResponseWriter, r *http.Request) {
	var resetOtpRequest models.PasswordResetOtpConfirmation
	requestErr := utils.DecodeJSONRequest(r, &resetOtpRequest)
	if requestErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Invalid request body")
		return
	}
	if resetOtpRequest.Email == "" || resetOtpRequest.Code == "" {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Email and code are required")
		return
	}

	otpCollection := utils.GetDatabaseCollection("otp")
	otpCtx, otpCancel := utils.GetDatabaseContext()
	defer otpCancel()

	var existingOtp models.OTP
	otpSelectionErr := otpCollection.FindOne(otpCtx, bson.D{
		{"operationType", "FORGOT_PASSWORD"},
		{"code", resetOtpRequest.Code},
		{"userEmail", resetOtpRequest.Email},
	}).Decode(&existingOtp)

	if errors.Is(otpSelectionErr, mongo.ErrNoDocuments) {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Invalid OTP")
		return
	}
	if otpSelectionErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		return
	}

	hasExceededAttemptCount, blockedTime, updatingOtpErr := helpers.OtpChecker(existingOtp)
	if updatingOtpErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		return
	} else if hasExceededAttemptCount {
		w.WriteHeader(http.StatusBadRequest)
		message := "You've exceeded the limit of attempts. Please try again after " + strconv.Itoa(blockedTime) + " minutes"
		utils.WriteResponse(w, message)
		return
	}

	diff := utils.GetDifferenceAbsTwoDatesInMinutes(existingOtp.CreationDate, utils.GetCurrentDateToTime())
	if diff > 5 {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "OTP has expired")
		return
	}

	otpCollection.FindOneAndUpdate(otpCtx, bson.D{
		{"_id", existingOtp.Id},
	}, bson.D{
		{"$set", bson.D{
			{"isVerified", true},
		}},
	})

	w.WriteHeader(http.StatusOK)
	utils.WriteResponse(w, "OTP confirmed successfully")
}

/*
@body

	email,
	password,
	passwordConfirmation
*/
func resetPassword(w http.ResponseWriter, r *http.Request) {
	var resetPasswordRequest models.PasswordResetRequest
	requestErr := utils.DecodeJSONRequest(r, &resetPasswordRequest)
	if requestErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Invalid request body")
		return
	}
	if resetPasswordRequest.Email == "" || resetPasswordRequest.Password == "" || resetPasswordRequest.PasswordConfirmation == "" {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Email, password and password confirmation are required")
		return
	}
	if resetPasswordRequest.Password != resetPasswordRequest.PasswordConfirmation {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "Password and confirmation do not match")
		return
	}

	otpCollection := utils.GetDatabaseCollection("otp")
	otpCtx, otpCancel := utils.GetDatabaseContext()
	defer otpCancel()
	var verifiedOtp models.OTP
	otpErr := otpCollection.FindOne(otpCtx, bson.D{
		{"userEmail", resetPasswordRequest.Email},
		{"operationType", "FORGOT_PASSWORD"},
		{"isVerified", true},
	}).Decode(&verifiedOtp)
	if errors.Is(otpErr, mongo.ErrNoDocuments) {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "OTP verification required")
		return
	}
	if otpErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		return
	}

	diff := utils.GetDifferenceAbsTwoDatesInMinutes(verifiedOtp.CreationDate, utils.GetCurrentDateToTime())
	if diff > 10 {
		w.WriteHeader(http.StatusBadRequest)
		utils.WriteResponse(w, "OTP has expired")
		return
	}

	usersCollection := utils.GetDatabaseCollection("users")
	ctx, cancel := utils.GetDatabaseContext()
	defer cancel()

	_, updateErr := usersCollection.UpdateOne(ctx, bson.D{
		{"email", resetPasswordRequest.Email},
		{"status", bson.M{"$ne": "ARCHIVED"}},
	}, bson.D{
		{"$set", bson.D{
			{"password", utils.GetHashedData(resetPasswordRequest.Password)},
		}},
	})
	if updateErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		return
	}

	authSessionCollection := utils.GetDatabaseCollection("auth-session")
	authSessionCollection.UpdateOne(ctx, bson.D{
		{"userEmail", resetPasswordRequest.Email},
	}, bson.D{
		{"$set", bson.D{
			{"connections", bson.A{}},
		}},
	})

	w.WriteHeader(http.StatusOK)
	utils.WriteResponse(w, "Password reset successfully")
}

func getMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := helpers.GetAuthClaims(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		utils.WriteResponse(w, "Unauthorized")
		return
	}

	response := map[string]any{
		"sub":      claims["sub"],
		"userId":   claims["userId"],
		"username": claims["username"],
		"email":    claims["email"],
		"roles":    claims["roles"],
	}

	render.JSON(w, r, response)
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
	r.Post("/reset-password/email", sendPasswordResetOtp)
	r.Post("/reset-password/otp", confirmPasswordResetOtp)
	r.Post("/reset-password", resetPassword)

	r.With(helpers.AuthMiddleware).Get("/me", getMe)
}
