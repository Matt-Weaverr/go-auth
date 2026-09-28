package main

import (
	"database/sql"
	"errors"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type Profile struct {
	Id                        int
	Name                      string
	Email                     string
	Password_Hash             string
	Tfa_Enabled               bool
	Tfa_Code                  *int
	Tfa_Code_Expiration       *int64
	Reset_Password_Token      *string
	Reset_Password_Expiration *int64
	Refresh_Token             *string
	Refresh_Token_Expiration  *int64
}

type Trusted_Device struct {
	UserId int
	DeviceFingerprint string
	Expiration int64
}

var db *sql.DB

func initDB() {
	dsn := CONFIG.Db_User + ":" + CONFIG.Db_Password + "@tcp(" + CONFIG.Db_Host + ":" + CONFIG.Db_Port + ")" + "/" + CONFIG.Db_Name
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
        (id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
		password_hash VARCHAR(100) NOT NULL,
		tfa_enabled BOOLEAN DEFAULT 0,
		tfa_code INT,
		tfa_code_expiration BIGINT,
		reset_password_token VARCHAR(100),
		reset_password_expiration BIGINT,
		refresh_Token VARCHAR(100),
		refresh_token_expiration BIGINT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`

	trusted_devices_table := `
	CREATE TABLE IF NOT EXISTS trusted_devices
		(user_id int NOT NULL,
		device_fingerprint VARCHAR(100) NOT NULL,
		expiration BIGINT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES profiles(id) ON DELETE CASCADE)`

	authorization_codes_table := `
	CREATE TABLE IF NOT EXISTS authorization_codes
		(code VARCHAR(100) NOT NULL,
		access_token VARCHAR(1000) NOT NULL,
		refresh_token VARCHAR(1000) NOT NULL,
		expiration BIGINT NOT NULL)`

	if _, err = d.Exec(profiles_table); err != nil {
		log.Fatal("Unable to create profiles_table")
	}

	if _, err = d.Exec(authorization_codes_table); err != nil {
		log.Fatal("Unable to create authorization_codes table")
	}

	if _, err = d.Exec(trusted_devices_table); err != nil {
		log.Fatal("Unable to create trusted_devices table")
	}

	db = d
	log.Printf("Successfully initialized database")
}

func insertProfile(email string, passwordhash string, name string) bool {

	stmt, err := db.Prepare("INSERT INTO profiles (name, email, password_hash) VALUES (?,?,?)")

	if err != nil {
		log.Printf("Error preparing insert statement: %v", err)
		return false
	}
	defer stmt.Close()

	_, err = stmt.Exec(name, email, passwordhash)

	if err != nil {
		log.Printf("Error inserting new profile to db: %v", err)
		return false
	}

	log.Printf("New profile created: %s, %s", name, email)
	return true
}

func insertTrustedDevice(user_id int, fingerprint string) bool {

	stmt, err := db.Prepare("INSERT INTO trusted_devices (user_id, device_fingerprint, expiration) VALUES (?,?,?)")

	if err != nil {
		log.Printf("Error preparing insert statement: %v", err)
		return false
	}
	defer stmt.Close()

	fingerprint_hash := computeHMAC256(fingerprint)

	_, err = stmt.Exec(user_id, fingerprint_hash, time.Now().Add(30*24*time.Hour).Unix())

	if err != nil {
		log.Printf("Error inserting trusted device to db: %v", err)
		return false
	}
	return true
}


func updateProfile(id int, column string, value any) error {
	stmt, err := db.Prepare("UPDATE profiles SET " + column + " = " + "? WHERE id = ?")

	if err != nil {
		log.Printf("Error preparing update statement: %v", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(value, id)

	if err != nil {
		log.Printf("Error updating profile: %v", err)
		return err
	}
	log.Printf("Updated profile with id %d: %s = %v", id, column, value)
	return nil
}

func deleteProfile(id int) {
	stmt, err := db.Prepare("DELETE FROM profiles WHERE id = ?")

	if err != nil {
		log.Printf("Error preparing delete statement: %v", err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(id)

	if err != nil {
		log.Printf("Error deleting profile: %v", err)
	}
	log.Printf("Deleted profile with id %d", id)
}

func readProfile(indentifier string, value any) (Profile, error) {
	var p Profile
	var query string
	switch indentifier {
	case "id":
		query = "SELECT id, name, email, password_hash, tfa_enabled, tfa_code, tfa_code_expiration, reset_password_token, reset_password_expiration, refresh_token, refresh_token_expiration FROM profiles WHERE id = ? LIMIT 1"
	case "email":
		query = "SELECT id, name, email, password_hash, tfa_enabled, tfa_code, tfa_code_expiration, reset_password_token, reset_password_expiration, refresh_token, refresh_token_expiration FROM profiles WHERE email = ? LIMIT 1"
	default:
		return Profile{}, errors.New("Invalid Identifier")
	}
	err := db.QueryRow(query, value).Scan(
		&p.Id,
		&p.Name,
		&p.Email,
		&p.Password_Hash,
		&p.Tfa_Enabled,
		&p.Tfa_Code,
		&p.Tfa_Code_Expiration,
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
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM profiles WHERE email = ? LIMIT 1)", email).Scan(&exists)
	if err != nil {
		log.Printf("Unable to query profiles table: %v", err)
		return true
	}
	return exists
}

func isTrustedDevice(user_id int, fingerprint string) bool {
    var device Trusted_Device

	fingerprint_hash := computeHMAC256(fingerprint)
    err := db.QueryRow(
        "SELECT * FROM trusted_devices WHERE user_id = ? AND device_fingerprint = ?",
        user_id,
        fingerprint_hash,
    ).Scan(&device.UserId, &device.DeviceFingerprint, &device.Expiration)

	if err != nil {
		return false
	}

	if device.Expiration <= time.Now().Unix() {
		return false
	}
	return true
}

func findUserInfoFromResetToken(token string) (int, int64) {
	var id int
	var expiration int64
	query := "SELECT id, reset_password_expiration FROM profiles WHERE reset_password_token = ? LIMIT 1"
	err := db.QueryRow(query, token).Scan(&id, &expiration)

	if err != nil {
		return -1, -1
	}

	return id, expiration
}

func generateAuthorization(accesstoken string, refreshtoken string) string {
	stmt, err := db.Prepare("INSERT INTO authorization_codes (code, access_token, refresh_token, expiration) VALUES (?,?,?,?)")

	if err != nil {
		log.Printf("Error preparing insert statement: %v", err)
		return ""
	}
	defer stmt.Close()

	authorizationcode, err := generateRandomToken(true)
	
	authcodestr := string(authorizationcode)
	_, err = stmt.Exec(authcodestr, accesstoken, refreshtoken, time.Now().Add(15*time.Minute).Unix())

	if err != nil {
		log.Printf("Error generating authorization code: %v", err)
		return ""
	}
	return authcodestr
}

func getTokens(code string) (int, string, string) {
	var refresh_token string
	var access_token string
	var expiration int64

	err := db.QueryRow("SELECT access_token, refresh_token, expiration FROM authorization_codes WHERE code = ?", code).Scan(&access_token, &refresh_token, &expiration)

	if expiration <= time.Now().Unix() {
		return -1, "", ""
	}

	if err != nil {
		log.Printf("Could not fetch tokens from db: %v", err)
		return -1, "", ""
	}

	return 0, refresh_token, access_token

}
