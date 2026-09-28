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
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/base64"
	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/bcrypt"
)

func generatePasswordHash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateRandomToken(encode bool) ([]byte, error) {
	bytes := make([]byte, 32)
	if _, err := cryptorand.Read(bytes); err != nil {
		return []byte{}, err
	}
	if !encode {
		return bytes, nil

	}
	return []byte(base64.RawURLEncoding.EncodeToString(bytes)), nil
}

func generateRandomInt(min int, max int) int {
	randomint := mathrand.Intn(max-min+1) + min
	return randomint
}

func sendEmail(to []string, subject string, body string) {

	auth := smtp.PlainAuth("", CONFIG.Smtp_User, CONFIG.Smtp_Password, CONFIG.Smtp_Host)

	message := []byte(
		"From: no-reply@conquerearthmc.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body,
	)
	err := smtp.SendMail(CONFIG.Smtp_Host + ":" + CONFIG.Smtp_Port, auth, CONFIG.Smtp_User, to, message)

	if err != nil {
		log.Printf("Failed to send email: %v", err)
		return
	}

	log.Printf("Email sent to: %v", to)
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

func verifySignature(data []byte, signature []byte, key any) bool {
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

func computeHMAC256(data string) string{
	h := hmac.New(sha256.New, []byte(CONFIG.Secret_Key))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func convertPublicKeyToPEMString(key *rsa.PublicKey) string{
	pubBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		log.Printf("Failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	pubKeyString := string(pubPEM)
	return pubKeyString
}

