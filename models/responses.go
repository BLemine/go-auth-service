package models

type LoginResponse struct {
	Token                  string `json:"token"`
	RefreshToken           string `json:"refreshToken"`
	TokenExpiration        int    `json:"tokenExpiration"`
	RefreshTokenExpiration int    `json:"refreshTokenExpiration"`
}

type BaseResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
