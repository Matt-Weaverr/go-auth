package main

import (
	"database/sql"
	"log"
	"errors"

	_ "github.com/go-sql-driver/mysql"
)

const DB_USER = "root"
const DB_PASSWORD = ""
const DB_ADDRESS = "localhost"
const DB_PORT = "3306"
const DB_NAME = "go-auth-service"

type Profile struct {
	Id int
	Name string
	Email string
	Password_Hash string
	Tfa_Enabled bool
	Tfa_Verified bool
	Tfa_Code int
	Tfa_Code_Expiration int64
	Reset_Password_Token string
	Reset_Password_Expiration int64
	Refresh_Token string
	Refresh_Token_Expiration int64
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

	log.Printf("Connected to database")

	profiles_table := `
	CREATE TABLE IF NOT EXISTS profiles
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
		password_hash VARCHAR(100) NOT NULL,
		tfa_enabled BOOLEAN DEFAULT 0,
		tfa_verified BOOLEAN DEFAULT 0,
		tfa_code INT,
		tfa_code_expiration BIGINT,
		reset_password_token INT,
		reset_password_expiration BIGINT,
		Refresh_Token VARCHAR(100),
		refresh_token_expiration BIGINT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`

	trusted_devices_table := `
	CREATE TABLE IF NOT EXISTS trusted_devices
		user_id int NOT NULL,
		device_fingerprint VARCHAR(100) NOT NULL`


	if _, err = d.Exec(profiles_table); err != nil {
		log.Fatal("Unable to create profile table")
	}

	if _,err = d.Exec(trusted_devices_table); err != nil {
		log.Fatal("Unable to creare trusted_devices table")
	}


	db = d
	log.Printf("Successfully initialized database")
}


func insert(email string, passwordhash string, name string) bool {
		
		stmt, err := db.Prepare("INSERT INTO profiles (name, email, password_hash) VALUES (?,?,?)")

		if err != nil {
			log.Printf("Error preparing insert statement: ", err)
			return false
		}
		defer stmt.Close()


		_, err = stmt.Exec(name, email, passwordhash)

		if err != nil {
			log.Printf("Error inserting new profile to db: ", err)
			return false
		}
		
		log.Printf("New profile created: %s, %s", p.Name, p.Email)
		return true
}

func update[T any](id int, column string, value T) error {
	stmt, err := db.Prepare("UPDATE profiles SET " + column + " = " + "? WHERE id = ?")

	if err != nil {
		log.Printf("Error preparing update statement: ", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(value, id)

	if err != nil {
		log.Printf("Error updating profile: ", err)
		return err
	}
	log.Printf("Updated profile with id %d: %s = %T", id, column, value)
	return nil
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
	log.Printf("Deleted profile with id %d", id)
}

func read[T any](key any) (Profile, error) {
	var p Profile
	var query string
	switch any(key).(type) {
	case int:
		query = "SELECT * FROM profiles WHERE id = ? LIMIT 1"
		break
	case string:
		query = "SELECT * FROM profiles WHERE email = ? LIMIT 1"
		break
	default:
		return Profile{}, errors.New("Invalid key type. Cannot read db")
	}
	err := db.QueryRow(query, key).Scan(
		&p.Id,
		&p.Name,
		&p.Email,
		&p.Password_Hash,
		&p.Tfa_Enabled
		&p.Tfa_Verified,
		&p.Tfa_Code,
		&p.Tfa_Code.Expiration,
		&p.Reset_Password_Token,
		&p.Reset_Password_Expiration,
		&p.Refresh_Token,
		&p.Refresh_Token_Expiration)

	if err != nil {
		return Profile{}, err
	}

	return p, nil
}

func emailExists(email string) bool {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM profiles WHERE email = ? LIMIT 1)", email).Scan(&email)
	if err != nil {
		log.Printf("Unable to query profiles table: ", err)
		return true
	}
	return exists
}

func isTrustedDevice(user_id int, fingerprint string) bool {
	var trusted bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM trusted_devices WHERE user_id = ? AND device_fingerprint = ?)",
	 user_id, 
	 fingerprint).Scan(&trusted)

	 if err != nil {
		log.Printf("Unable to query trusted_devices table: ", err)
		return false
	 }
	 return trusted
}

