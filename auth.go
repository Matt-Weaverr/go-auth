package main

import (
	"log"
	"time"

)
/*
Login status codes
-1 = could not find user
1 = incorrect password
2 = refresh token failed
4 = tfa auth required
0 = successful login
*/
func login(email string, password string, devicefingerprint string) (int, string, string) {
	p, err := read[string](email)
	if err != nil {
		log.Printf("Failed to find user in db (%s)", email)
		return -1, "", ""
	}
	
	if !checkPassword(password, p.Password_Hash) {
		log.Printf("Failed login attempt (%s)", email)
		return 1, "", ""
	}

	if p.Tfa_Enabled && !isTrustedDevice(p.Id, devicefingerprint){
		return 4, "", ""
	}
	refreshtoken, err := generateRandomToken(16)
	if err != nil {
		log.Printf("Failed to generate refresh token for user %s", email)
		return  2, "", ""
	}
	err = update[string](p.Id, "refresh_token", refreshtoken)
	err = update[int64](p.Id, "refresh_token_expiration", time.Now().Add(168*time.Hour).Unix())

	if err != nil {
		return 2, "", ""
	}

	accesstoken := generateJWT(p.Id, p.Email, p.Name)

	return 0, refreshtoken, accesstoken

}

/*
Register status codes
-1 = email exists
1 = Couldnt generate password hash
2 = couldnt insert into db
0 = Successful
*/
func register(name string, email string, password string) int {
	if emailExists(email) {	
		return -1
	}
	passwordhash, err := generatePasswordHash(password)
	if err != nil {
		log.Printf("Failed to generate password hash for new user %s", email)
		return 1
	}
	if !insert(email, passwordhash, name) {
		log.Printf("Failed to create user %s", email)
		return 2
	}
	log.Printf("Successfully created new user %s", email)
	return 0
}

func enableTfa(id int) {
	
}

func verifyTfa(id int, code int) int {
	p, err := read[int](id)
	if err != nil {
		return -1
	}
	
	if !p.Tfa_Enabled {
		return 1
	}

	err := update[int](p.Id, "tfa_code", generateRandomInt(100000, 999999))
	err := update[int64](p.Id, "tfa_code_expiration", time.Now().Add(5*time.Minute).Unix())

	if err != nil {
		log.Printf("Could not update user tfa code in db %s", p.Email)
		return -1
	}

	if p.Tfa_Code != code || p.Tfa_Code_Expiration <= time.Now().Unix() {
		return 2
	}
	return 0
}

