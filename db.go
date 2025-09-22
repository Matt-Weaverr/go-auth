package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

const DB_USER = "root"
const DB_PASSWORD = ""
const DB_ADDRESS = "localhost"
const DB_PORT = "3306"
const DB_NAME = "go-auth-service"

type profile struct {
	ID int
	Name string
	email string
	Password string
	Tfa_Verified boolean
	Tfa_Code string
	Tfa_Expiration long
	Reset_Password_Token string
	Reset_Password_Expiration long
	Refresh_Token string
	Refresh_Token_Expiration long
}


func connect() {
	dsn := DB_USER + ":" + DB_PASSWORD + "@tcp(" + DB_ADDRESS + ":" + DB_PORT + "/" + DB_NAME

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Could not open database: ", err)
	}
	defer db.close()

	if err := db.Ping(); err != nil {
    log.Fatal("Database unreachable: ", err)
}
fmt.Println("Connected to MySQL")
}

func insert(p profile) {

}

func update[T any](id int, column string, value T) {
	
}

func delete(id int) {

}

func read(id int) {

}

