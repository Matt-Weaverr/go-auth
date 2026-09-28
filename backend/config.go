package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Db_Host string
	Db_Port string
	Db_User string
	Db_Password string
	Db_Name string
	Smtp_Host string
	Smtp_Port string
	Smtp_Password string
	Smtp_User string
	Domain string
	Dev_Mode bool
	Private_Key *rsa.PrivateKey
	Public_Key *rsa.PublicKey
	Secret_Key string
	Refresh_Token_Expiration int
}

var CONFIG Config

func initConfig() {

	err := godotenv.Load()

	if err != nil {
		log.Fatal("Error loading .env file")
		return
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)

	CONFIG.Private_Key = key
	CONFIG.Public_Key = &key.PublicKey
	CONFIG.Db_Host = os.Getenv("DB_HOST")
	CONFIG.Db_Port = os.Getenv("DB_Port")
	CONFIG.Db_User = os.Getenv("DB_USER")
	CONFIG.Db_Password = os.Getenv("DB_PASSWORD")
	CONFIG.Db_Name = os.Getenv("DB_NAME")
	CONFIG.Smtp_Host = os.Getenv("SMTP_HOST")
	CONFIG.Smtp_Port = os.Getenv("SMTP_PORT")
	CONFIG.Smtp_Password = os.Getenv("SMTP_PASSWORD")
	CONFIG.Smtp_User = os.Getenv("SMTP_USER")
	CONFIG.Domain = os.Getenv("DOMAIN")

	secret_key, err := generateRandomToken(false)
	 
	CONFIG.Secret_Key = string(secret_key)

	devmode, err := strconv.ParseBool(os.Getenv("DEV_MODE"))

	CONFIG.Dev_Mode = devmode

	minutes, err := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRATION"))

	CONFIG.Refresh_Token_Expiration = minutes

	if err != nil {
		log.Fatal("Failed to load config")
	}
}