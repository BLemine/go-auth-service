package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"go-auth-service/assets"
	"go-auth-service/config"
	"go-auth-service/models"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"
)

func SendMail(request models.SendMailRequest) error {
	mailerConfig, configErr := config.GetMailingProviderConfig()
	if configErr != nil {
		return configErr
	}

	marshalled, _ := json.Marshal(request)

	httpRequest, sendingMailError := http.NewRequest("POST", mailerConfig.Url, bytes.NewReader(marshalled))

	if httpRequest != nil {
		httpRequest.Header.Set("accept", "application/json")
		httpRequest.Header.Set("api-key", mailerConfig.ApiKey)
	}

	client := http.Client{Timeout: 10 * time.Second}

	sendingMailResponse, err := client.Do(httpRequest)

	if err != nil {
		log.Printf("impossible to send request: %s\n", err)
		return err
	}

	if sendingMailResponse.StatusCode < 200 || sendingMailResponse.StatusCode >= 300 {
		b, _ := io.ReadAll(sendingMailResponse.Body)
		return fmt.Errorf("brevo returned %d: %s", sendingMailResponse.StatusCode, b)
	}

	return sendingMailError
}

var tmpl = template.Must(template.ParseFS(assets.Templates, "templates/*.html"))

func RenderTemplate(name string, data any) (string, error) {
	var buf bytes.Buffer
	err := tmpl.ExecuteTemplate(&buf, name, data)
	return buf.String(), err
}

func GenerateOTP() (string, error) {
	// Generate a random number between 0 and 999999
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	// Format with leading zeros to ensure it’s always 6 digits
	return fmt.Sprintf("%06d", n.Int64()), nil
}
