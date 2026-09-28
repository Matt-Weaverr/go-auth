package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
	"strconv"
)

/*
Login status codes
-1 = could not find user
1 = incorrect password
2 = refresh token failed
4 = tfa auth required
0 = successful login
*/

func login(email string, password string, devicefingerprint string) (int, string, string, string, Profile) {
	p, err := readProfile("email", email)
	if err != nil {
		log.Printf("Failed to find user in db (%s)", email)
		log.Print(err)
		return -1, "", "", "", Profile{}
	}
	
	if !checkPassword(password, p.Password_Hash) {
		log.Printf("Failed login attempt (%s)", email)
		return 1, "", "", "", Profile{}
	}

	if p.Tfa_Enabled && !isTrustedDevice(p.Id, devicefingerprint) {
		status := sendTfa(p.Id)

		if !status {
			log.Printf("Could not update user tfa code in db %s", p.Email)
			return -1, "", "", "", Profile{}
		}

		log.Printf("Login attempt awaiting TFA for user %s", p.Email)
		return 4, "", "", generatePreAuthToken(p.Id), Profile{}
	}

	status, refreshtoken, accesstoken := generateAuthTokens(p.Id, p.Email, p.Name)

	if !status {
		return 2, "", "", "", Profile{}
	}

	log.Printf("Successful login for user %s", email)
	return 0, refreshtoken, accesstoken, "", p
}

func generateAuthTokens(id int, email string, name string) (bool, string, string) {
	refreshtoken, err := generateRandomToken(true)
	refreshtokenstr := string(refreshtoken)
	if err != nil {
		log.Printf("Failed to generate refresh token for user (%s)", email)
		log.Print(err)
		return  false, "", ""
	}
	err = updateProfile(id, "refresh_token", refreshtokenstr)
	err = updateProfile(id, "refresh_token_expiration", time.Now().Add(time.Duration(CONFIG.Refresh_Token_Expiration) * time.Minute).Unix())

	if err != nil {
		return false, "", ""
	}

	accesstoken := generateAccessJWT(id, email, name)

	return true, refreshtokenstr, accesstoken
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
	if !insertProfile(email, passwordhash, name) {
		log.Printf("Failed to create user %s", email)
		return 2
	}
	log.Printf("Successfully created new user %s", email)
	return 0
}

func sendTfa(id int) bool {
	otp := generateRandomInt(100000, 999999)

	p, err := readProfile("id", id)

	if err != nil {
		log.Printf("Could not fetch user data when sending tfa")
		return false
	}

	err = updateProfile(id, "tfa_code", otp)
	err = updateProfile(id, "tfa_code_expiration", time.Now().Add(5*time.Minute).Unix())

	otp_string := strconv.Itoa(otp)

	sendEmail(
		[]string{p.Email},
		"TFA Otp \n",
		"Here is your one time pin for tfa: " + otp_string)

	if err != nil {
		log.Printf("Could not update user tfa code in db for id %d", id)
		return false
	}
	return true
}

func verifyTfa(id int, code int) int {
	p, err := readProfile("id", id)
	if err != nil {
		return -1
	}

	if *p.Tfa_Code != code || *p.Tfa_Code_Expiration <= time.Now().Unix() {
		return 2
	}

	if !p.Tfa_Enabled {
		err = updateProfile(p.Id, "tfa_enabled", 1)
		if err != nil {
			return -1
		}
	}
	return 0
}

func generatePreAuthToken(id int) string {
	data := Pre_Auth{
		User_Id: id,
		Exp:     time.Now().Add(5 * time.Minute).Unix(),
	}

	datajson, _ := json.Marshal(data)
	datastring := base64.RawURLEncoding.EncodeToString(datajson)

	h := hmac.New(sha256.New, []byte(CONFIG.Secret_Key))
	h.Write([]byte(datastring))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return datastring + "." + sig
}

func verifyPreAuthToken(token string) (bool, int) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false, -1
	}

	sig := parts[1]
	data := parts[0]

	h := hmac.New(sha256.New, []byte(CONFIG.Secret_Key))
	h.Write([]byte(data))
	expectedsig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedsig)) {
		return false, -1
	}

	datadec, _ := base64.RawURLEncoding.DecodeString(data)
	var p Pre_Auth
	json.Unmarshal(datadec, &p)

	if time.Now().Unix() > p.Exp {
		return false, -1
	}

	return true, p.User_Id
}

func setUserAuthCookie(w http.ResponseWriter, user_id string, refresh_token string) {
	securemode := true
	if CONFIG.Dev_Mode {
		securemode = false
	}

	sig, err := generateSignature([]byte(user_id+"."+refresh_token), []byte(CONFIG.Secret_Key))
	if err != nil {
		log.Printf("Failed to generate signature for user auth cookie: %v", err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    user_id + "." + refresh_token + "." + base64.RawURLEncoding.EncodeToString(sig),
		Expires:  time.Now().Add(time.Duration(CONFIG.Refresh_Token_Expiration) * time.Minute),
		Path:     "/",
		HttpOnly: true,
		Secure:   securemode,
		SameSite: http.SameSiteLaxMode,
	})
}

func logout(w http.ResponseWriter, user_id int) bool {
	securemode := true
	if CONFIG.Dev_Mode {
		securemode = false
	}
	err := updateProfile(user_id , "refresh_token_expiration", 0)
	if err != nil {
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,                         
		Secure:   securemode,                         
		SameSite: http.SameSiteLaxMode,      
	})
	return true
}

