package config

import (
	"os"
)

type MissingMailerConfigError struct{}

func (e MissingMailerConfigError) Error() string {
	return "missing mailer config (BREVO_API_URL / BREVO_API_KEY)"
}

type MailerConfig struct {
	Url    string
	ApiKey string
}

type CommonConfig struct {
	SupportEmail string
	SourceName   string
}

func GetMailingProviderConfig() (MailerConfig, error) {
	url := os.Getenv("BREVO_API_URL")
	apiKey := os.Getenv("BREVO_API_KEY")
	if url == "" || apiKey == "" {
		return MailerConfig{}, MissingMailerConfigError{}
	}
	return MailerConfig{
		Url:    os.Getenv("BREVO_API_URL"),
		ApiKey: os.Getenv("BREVO_API_KEY"),
	}, nil
}

func GetMailingCommonConfig() (CommonConfig, error) {
	supportEmail := os.Getenv("SUPPORT_EMAIL")
	if supportEmail == "" {
		return CommonConfig{}, MissingMailerConfigError{}
	}
	return CommonConfig{
		SupportEmail: os.Getenv("SUPPORT_EMAIL"),
		SourceName:   os.Getenv("MAILER_SOURCE_NAME"),
	}, nil
}
