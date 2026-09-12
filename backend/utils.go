package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"log"
	mathrand "math/rand"
	"net/smtp"
	"os"
	cryptorand "crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generatePasswordHash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)

	_, err := cryptorand.Read(bytes)

	if err != nil {
		return "", err
	}
	l := len(charset)
	for i, b := range bytes {
		bytes[i] = charset[b%byte(l)]
	}
	return string(bytes), nil
}

func generateRandomInt(min int, max int) int {
	randomint := mathrand.Intn(max-min+1) + min
	return randomint
}

func sendEmail(from string, to []string, subject string, body string) {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	password := os.Getenv("SMTP_PASSWORD")

	message := []byte(subject + "\n" + body)

	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		log.Printf("Failed to send password reset email: %v", err)
	}

	log.Printf("Password reset email sent to: %v", to)
}

func generateSignature(data []byte, key any) ([]byte, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		if key == nil {
			return nil, errors.New("RSA private key is nil")
		}

		hash := sha256.Sum256(data)
		return rsa.SignPKCS1v15(cryptorand.Reader, key, crypto.SHA256, hash[:])
	case []byte:
		if len(key) == 0 {
			return nil, errors.New("secret key is empty")
		}

		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil), nil
	default:
		return nil, errors.New("signature key must be an RSA private key or secret key")
	}
}

func verifySignature(data, signature []byte, key any) bool {
	switch key := key.(type) {
	case *rsa.PublicKey:
		if key == nil {
			return false
		}
		hash := sha256.Sum256(data)
		err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature)
		return err == nil
	case []byte:
		if len(key) == 0 {
			return false
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		if !hmac.Equal(mac.Sum(nil), signature) {
			return false
		}
		return true
	default:
		return false
	}
}

