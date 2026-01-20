package main

import (
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"time"
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

	_, err := rand.Read(bytes)

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
	rand.Seed(time.Now().UnixNano())
	randomint := rand.Intn(max-min+1) + min
	return randomint
}

