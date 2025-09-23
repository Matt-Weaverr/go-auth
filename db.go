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

type Profile struct {
	Name string
	Email string
	Password_Hash string
	Tfa_Verified bool
	Tfa_Code string
	Tfa_Expiration uint64
	Reset_Password_Token string
	Reset_Password_Expiration uint64
	Refresh_Token string
	Refresh_Token_Expiration uint64
}

var db *sql.DB

func initDB() {
	dsn := DB_USER + ":" + DB_PASSWORD + "@tcp(" + DB_ADDRESS + ":" + DB_PORT + "/" + DB_NAME

	d, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Could not open database: ", err)
	}

	if err := d.Ping(); err != nil {
    log.Fatal("Database unreachable: ", err)
	}

	fmt.Println("Connected to database")

	q := `
	CREATE TABLE IF NOT EXISTS profiles
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
		password_hash VARCHAR(100) NOT NULL,
		tfa_verified BOOLEAN DEFAULT 0,
		tfa_code VARCHAR(100),
		tfa_expiration BIGINT,
		reset_password_token INT,
		reset_password_expiration BIGINT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`

		_, err = d.Exec(q)

		if err != nil {
			log.Fatal("Unable to create table")
		}
		db = d
		fmt.Println("Successfully initialized database")
}


func insert(p Profile) {
		
		stmt, err := db.Prepare("INSERT INTO profiles (name, email, password_hash) VALUES (?,?,?)")

		if err != nil {
			log.Printf("Error preparing insert statement: ", err)
			return
		}
		defer stmt.Close()


		_, err = stmt.Exec(p.Name, p.Email, p.Password_Hash)

		if err != nil {
			log.Printf("Error inserting new profile to db: ", err)
			return
		}
		
		fmt.Println("New profile created: %s, %s", p.Name, p.Email)
}

func update[T any](id int, column string, value T) {
	stmt, err := db.Prepare("UPDATE profiles SET " + column + " = " + "? WHERE id = ?")

	if err != nil {
		log.Printf("Error preparing update statement: ", err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(value, id)

	if err != nil {
		log.Printf("Error updating profile: ", err)
	}
	fmt.Println("Updated profile with id %d: %s = %T", id, column, value)
}

func delete(id int) {
		stmt, err := db.Prepare("DELETE FROM profiles WHERE id = ?")

	if err != nil {
		log.Printf("Error preparing delete statement: ", err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(id)

	if err != nil {
		log.Printf("Error deleting profile: ", err)
	}
	fmt.Println("Deleted profile with id %d", id)
}

func read(id int) (Profile, error) {
	var p Profile
	err := db.QueryRow("SELECT * FROM profiles WHERE id = ?", id).Scan(
		&p.Name,
		&p.Email,
		&p.Password_Hash,
		&p.Tfa_Verified,
		&p.Tfa_Code,
		&p.Tfa_Expiration,
		&p.Reset_Password_Token,
		&p.Reset_Password_Expiration,
		&p.Refresh_Token,
		&p.Refresh_Token_Expiration)

	if err != nil {
		return Profile{}, err
	}

	return p, nil
}

