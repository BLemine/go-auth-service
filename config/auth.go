package config

import (
	"os"
	"strconv"
)

type TokenConfig struct {
	TokenSecretKey                string
	TokenExpirationInMinutes      int
	RefreshTokenExpirationInHours int
}

type JWTConfigError struct {
	Message string
}

func (e JWTConfigError) Error() string {
	return e.Message
}

func GetJWTConfig() (TokenConfig, error) {
	tokenSecretKey := os.Getenv("TOKEN_SECRET_KEY")
	tokenExpirationInMinutesStr := os.Getenv("TOKEN_EXPIRATION_IN_MINUTES")
	refreshTokenExpirationInHoursStr := os.Getenv("REFRESH_TOKEN_EXPIRATION_IN_HOURS")

	tokenExpirationInMinutes, tokenConversionErr := strconv.Atoi(tokenExpirationInMinutesStr)
	refreshTokenExpirationInHours, refreshTokenConversionErr := strconv.Atoi(refreshTokenExpirationInHoursStr)

	if tokenConversionErr != nil || refreshTokenConversionErr != nil {
		return TokenConfig{}, JWTConfigError{Message: "Oops couldn't convert the JWT environment variables to integers"}
	}

	return TokenConfig{
		TokenSecretKey:                tokenSecretKey,
		TokenExpirationInMinutes:      tokenExpirationInMinutes,
		RefreshTokenExpirationInHours: refreshTokenExpirationInHours,
	}, nil
}
