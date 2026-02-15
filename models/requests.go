package models

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type SignUpEmailValidation struct {
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Email     string `json:"email"`
}

type SignUpEmailOtpConfirmation struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type SignUpPersonalDetailsRequest struct {
	Email                string `json:"email"`
	Password             string `json:"password"`
	PasswordConfirmation string `json:"passwordConfirmation"`
}

type LogoutRequest struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

type PasswordResetEmailRequest struct {
	Email string `json:"email"`
}

type PasswordResetOtpConfirmation struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type PasswordResetRequest struct {
	Email                string `json:"email"`
	Password             string `json:"password"`
	PasswordConfirmation string `json:"passwordConfirmation"`
}

// SendMailRequest for sending email
type SendMailRequest struct {
	Source       MailSource        `json:"sender"`
	Destinations []MailDestination `json:"to"`
	Subject      string            `json:"subject"`
	Body         string            `json:"htmlContent"`
}

type MailSource struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type MailDestination struct {
	Email string `json:"email"`
}
