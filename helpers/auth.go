package helpers

import (
	"go-auth-service/config"
	"go-auth-service/models"
	"go-auth-service/utils"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type AuthError struct {
	Code    int
	Message string
}

func (e AuthError) Error() string {
	return e.Message
}

func sendOtpMail(w http.ResponseWriter, email string) {
	htmlContent, err := utils.RenderTemplate("email-verification.html", map[string]any{
		"verificationCode":  "123456",
		"validityInMinutes": 5,
	})
	if err != nil {
		log.Println("template render error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// loading mailing common config
	commonMailingConfig, mailingConfigErr := config.GetMailingCommonConfig()
	if mailingConfigErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Couldn't load 'mailing-common' config with error:", mailingConfigErr)
		return
	}

	sendingMailErr := utils.SendMail(
		models.SendMailRequest{
			Source: models.MailSource{
				Name:  commonMailingConfig.SourceName,
				Email: commonMailingConfig.SupportEmail,
			},
			Destinations: []models.MailDestination{
				{
					Email: email,
				},
			},
			Subject: "Email Verification Code",
			Body:    htmlContent,
		},
	)
	if sendingMailErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		log.Println("Oops couldn't send the mail", sendingMailErr)
		return
	}
}

// OtpChecker returns (hasExceededAttemptCount, error)
func OtpChecker(existingOtp models.OTP) (bool, int, error) {
	otpCollection := utils.GetDatabaseCollection("otp")
	otpCtx, otpCancel := utils.GetDatabaseContext()
	defer otpCancel()

	if existingOtp.AttemptCount < 3 {
		// do nothing in the step of sending-email-verification-code
		// increment existingOtp.AttemptCount in the otp-confirmation step
		existingOtp.AttemptCount += 1
		// Persist the changes to database
		_, updateErr := otpCollection.UpdateOne(otpCtx, bson.D{
			{"_id", existingOtp.Id},
		}, bson.D{
			{"$set", bson.D{
				{"attemptCount", existingOtp.AttemptCount},
			}},
		})

		return false, 0, updateErr

	} else {
		// check diff creationDate with currentDate
		diff := utils.GetDifferenceAbsTwoDatesInMinutes(existingOtp.CreationDate, utils.GetCurrentDateToTime())
		if diff > 3 {
			existingOtp.AttemptCount = 0
			existingOtp.CreationDate = utils.GetCurrentDateToTime()

			// Persist the changes to database
			_, updateErr := otpCollection.UpdateOne(otpCtx, bson.D{
				{"_id", existingOtp.Id},
			}, bson.D{
				{"$set", bson.D{
					{"attemptCount", existingOtp.AttemptCount},
					{"creationDate", existingOtp.CreationDate},
				}},
			})

			return false, 0, updateErr

		} else {
			return true, diff, nil
		}
	}
}

func HandleOtpCreation(w http.ResponseWriter, r *http.Request, userEmail string, operationType string) {
	// Email OTP handling
	otpCollection := utils.GetDatabaseCollection("otp")
	otpCtx, otpCancel := utils.GetDatabaseContext()
	defer otpCancel()

	var existingOtp models.OTP
	otpSelectionErr := otpCollection.FindOne(otpCtx, bson.D{
		{"userEmail", userEmail},
		{"operationType", operationType},
	}).Decode(&existingOtp)

	if otpSelectionErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		utils.WriteResponse(w, "Internal server error")
		log.Println("Oops an error occurred during finding otp ::: ", otpSelectionErr)
		return
	}

	if existingOtp.Id != bson.NilObjectID {
		// check attemptCount
		if existingOtp.AttemptCount < 3 {
			// do nothing in the step of sending-email-verification-code
			// increment existingOtp.AttemptCount in the otp-confirmation step
		} else {
			// check diff creationDate with currentDate
			diff := utils.GetDifferenceAbsTwoDatesInMinutes(existingOtp.CreationDate, utils.GetCurrentDateToTime())
			if diff > 3 {
				existingOtp.AttemptCount = 0
				existingOtp.CreationDate = utils.GetCurrentDateToTime()

				// Persist the changes to database
				_, updateErr := otpCollection.UpdateOne(otpCtx, bson.D{
					{"_id", existingOtp.Id},
				}, bson.D{
					{"$set", bson.D{
						{"attemptCount", existingOtp.AttemptCount},
						{"creationDate", existingOtp.CreationDate},
					}},
				})

				if updateErr != nil {
					w.WriteHeader(http.StatusInternalServerError)
					utils.WriteResponse(w, "Internal server error")
					log.Println("Oops couldn't update the otp::: ", updateErr)
					return
				}

				// Brevo API call
				sendOtpMail(w, userEmail)
				render.JSON(w, r, "Check your email for the verification code")
			} else {
				w.WriteHeader(http.StatusBadRequest)
				message := "You've already exceeded the limit of attempts. Please try again after " + strconv.Itoa(diff) + " minutes"
				render.JSON(w, r, message)
				return
			}
		}
	} else {
		// create a new otp
		otpCode, otpCreationErr := utils.GenerateOTP()
		if otpCreationErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			utils.WriteResponse(w, "Internal server error")
			log.Println("Oops couldn't generate the otp::: ", otpCreationErr)
			return
		}
		_, insertionErr := otpCollection.InsertOne(otpCtx, bson.D{
			{"userEmail", userEmail},
			{"operationType", operationType},
			{"attemptCount", 0},
			{"creationDate", utils.GetCurrentDateToTime()},
			{"code", otpCode},
		})

		if insertionErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			utils.WriteResponse(w, "Internal server error")
			log.Println("Oops couldn't insert the otp::: ", insertionErr)
			return
		}
		// Brevo API call
		sendOtpMail(w, userEmail)
		//successCallback()
		render.JSON(w, r, "Check your email for the verification code")
	}

}

func GetAccessToken(user models.User) (string, string, int, int, error) {
	baseUrl := os.Getenv("BASE_URL")

	jwtConfig, jwtConfigErr := config.GetJWTConfig()

	if jwtConfigErr != nil {
		return "", "", 0, 0, jwtConfigErr
	}

	var tokenStr string
	var refreshTokenStr string

	key := []byte(jwtConfig.TokenSecretKey)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"iss":      baseUrl,
			"sub":      user.Id.Hex(),
			"username": user.Username,
			"userId":   user.Id,
			"roles":    user.Roles,
			"email":    user.Email,
			"exp":      time.Now().Add(time.Duration(jwtConfig.TokenExpirationInMinutes) * time.Minute).Unix(), // Token expires in 24 hours
		})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"iss":   baseUrl,
			"sub":   user.Id.Hex(),
			"email": user.Email,
			"exp":   time.Now().Add(time.Duration(jwtConfig.RefreshTokenExpirationInHours) * time.Hour).Unix(), // Token expires in 24 hours
		})

	tokenStr, tokenSigningErr := token.SignedString(key)
	refreshTokenStr, refreshTokenSigningErr := refreshToken.SignedString(key)

	if tokenSigningErr != nil || refreshTokenSigningErr != nil {
		return "", "", 0, 0, AuthError{Code: 001, Message: "Oops couldn't sign the token"}
	}

	return tokenStr, refreshTokenStr, jwtConfig.TokenExpirationInMinutes, jwtConfig.RefreshTokenExpirationInHours, nil
}

func PersistAuthSession(tokenStr string, refreshTokenStr string, tokenExpirationInMinutes int, userEmail string) error {
	authSessionCollection := utils.GetDatabaseCollection("auth-session")
	authSessionCtx, authSessionCancel := utils.GetDatabaseContext()
	defer authSessionCancel()

	sessionDoc := bson.D{
		{"token", tokenStr},
		{"refreshToken", refreshTokenStr},
		{"expiration", tokenExpirationInMinutes},
		{"creationDate", bson.NewDateTimeFromTime(time.Now())},
	}

	_, sessionErr := authSessionCollection.UpdateOne(
		authSessionCtx,
		bson.D{{"userEmail", userEmail}}, // filter
		bson.D{{"$push", bson.D{{"connections", sessionDoc}}}}, // update
		options.UpdateOne().SetUpsert(true),
	)

	if sessionErr != nil {
		return sessionErr
	}

	// clean up old sessions
	cutoff := bson.NewDateTimeFromTime(time.Now().Add(-1 * time.Hour))

	_, oldSessionsDeletionErr := authSessionCollection.UpdateMany(
		authSessionCtx,
		bson.D{}, // all auth-session docs
		bson.D{{"$pull", bson.D{
			{"connections", bson.D{
				{"creationDate", cutoff}},
			}},
		}},
	)

	// this isn't a critical error and not blocking the flow
	if oldSessionsDeletionErr != nil {
		log.Println("Oops couldn't delete the old sessions::: ", oldSessionsDeletionErr)
	}

	return nil
}
