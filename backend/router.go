package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"strconv"
)

type Auth_Response struct {
	Tfa_Required       bool   `json:"tfa_required"`
	Pre_Auth_Token     string `json:"pre-auth_token"`
	Authorization_Code string `json:"authorization_code"`
	Error              bool   `json:"error"`
	Message            string `json:"message"`
}

type New_User struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type User struct {
	Email           string `json:"email"`
	Password        string `json:"password"`
	Remember_Device bool   `json:"remember_device"`
	Dfp             string `json:"dfp"`
}

type Tfa struct {
	Otp   int    `json:"otp"`
	Token string `json:"token"`
}

type Tfa_Response struct {
	Error   bool   `json:"error"`
	Message string `json:"message"`
}

type Refresh_Request struct {
	User_Id       int    `json:"user-id"`
	Refresh_Token string `json:"refresh_token"`
}

type Refresh_Response struct {
	Valid        bool   `json:"valid"`
	Access_Token string `json:"access_token"`
}

type Reset_Password_Response struct {
	Error bool `json:"error"`
	Message string `json:"message"`
}

func initRouter() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {

		var u User

		err := json.NewDecoder(r.Body).Decode(&u)

		defer r.Body.Close()

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		status, refreshtoken, accesstoken, preauthtoken, profile := login(u.Email, u.Password, u.Dfp)

		/*
			-1 = could not find user
			1 = incorrect password
			2 = refresh token failed
			4 = tfa auth required
			0 = successful login
		*/

		authorization_code := generateAuthorization(accesstoken, refreshtoken)

		w.Header().Set("Content-Type", "application/json")

		switch status {
		case -1, 1:
			err := json.NewEncoder(w).Encode(Auth_Response{
				Tfa_Required:       false,
				Pre_Auth_Token:     "",
				Authorization_Code: "",
				Error:              true,
				Message:            "Email or password is incorrect"})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case 4:
			err := json.NewEncoder(w).Encode(Auth_Response{
				Tfa_Required:       true,
				Pre_Auth_Token:     preauthtoken,
				Error:              false,
				Authorization_Code: "",
				Message:            ""})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case 0:
			if u.Remember_Device {
				//update db
			}
			//this is used to authenticate on the edit user page
			setUserAuthCookie(w, strconv.Itoa(profile.Id), refreshtoken)

			err := json.NewEncoder(w).Encode(Auth_Response{
				Tfa_Required:       false,
				Pre_Auth_Token:     "",
				Error:              false,
				Authorization_Code: authorization_code,
				Message:            ""})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		default:
			err := json.NewEncoder(w).Encode(Auth_Response{
				Tfa_Required:       false,
				Error:              true,
				Authorization_Code: "",
				Message:            "Failed to login. Please try again later"})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		}
	})

	/*
		Register status codes
		-1 = email exists
		1 = Couldnt generate password hash
		2 = couldnt insert into db
		0 = Successful
	*/
	mux.HandleFunc("/api/register", func(w http.ResponseWriter, r *http.Request) {

		var u New_User
		w.Header().Set("Content-Type", "application/json")

		err := json.NewDecoder(r.Body).Decode(&u)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		defer r.Body.Close()

		status := register(u.Name, u.Email, u.Password)

		switch status {
		case -1:
			err := json.NewEncoder(w).Encode(Auth_Response{
				Tfa_Required:       false,
				Error:              true,
				Authorization_Code: "",
				Message:            "Email already exists"})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case 0:
			err := json.NewEncoder(w).Encode(Auth_Response{
				Tfa_Required:       false,
				Error:              false,
				Authorization_Code: "",
				Message:            ""})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		default:
			err := json.NewEncoder(w).Encode(Auth_Response{
				Tfa_Required:       false,
				Error:              true,
				Authorization_Code: "",
				Message:            "Failed to create new user. Please try again later"})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		}

	})

	mux.HandleFunc("/api/verify-tfa", func(w http.ResponseWriter, r *http.Request) {

		var tfa Tfa

		w.Header().Set("Content-Type", "application/json")

		err := json.NewDecoder(r.Body).Decode(&tfa)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		defer r.Body.Close()

		status, id := verifyPreAuthToken(tfa.Token)

		if !status {
			http.Error(w, "Could not verify pre auth", http.StatusForbidden)
			return
		}

		verification_status := verifyTfa(id, tfa.Otp)

		if verification_status == -1 {
			http.Error(w, "Could not find user profile", http.StatusForbidden)
			return
		}

		if verification_status == 2 {
			json.NewEncoder(w).Encode(map[string]any{
				"error":   true,
				"message": "Invalid verification code",
			})
			return
		}

		user, err := readProfile("id", id)
		if err != nil {
			http.Error(w, "Could not find user profile", http.StatusForbidden)
			return
		}

		status, refreshToken, accessToken := generateAuthTokens(user.Id, user.Email, user.Name)
		if !status {
			http.Error(w, "Could not generate auth tokens", http.StatusInternalServerError)
			return
		}

		authorizationCode := generateAuthorization(accessToken, refreshToken)
		if authorizationCode == "" {
			http.Error(w, "Could not create authorization code", http.StatusInternalServerError)
			return
		}

		setUserAuthCookie(w, strconv.Itoa(user.Id), refreshToken)


		json.NewEncoder(w).Encode(map[string]any{
			"error":              false,
			"message":            "",
			"authorization_code": authorizationCode,
		})

	})

	mux.HandleFunc("/api/authorization", func(w http.ResponseWriter, r *http.Request) {

		query := r.URL.Query()

		code := query.Get("code")

		status, refresh_token, access_token := getTokens(code)

		if status == -1 {
			http.Error(w, "Failed to find codes", http.StatusNotFound)
			return
		}

		err := json.NewEncoder(w).Encode(map[string]string{
			"refresh-token": refresh_token,
			"access-token":  access_token,
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	})

	mux.HandleFunc("/api/public-key", func(w http.ResponseWriter, r *http.Request) {

		key := loadRSAPublicKeyFromPEM("keys/public-key.pem")

		if key == nil {
			http.Error(w, "Failed to get public key", http.StatusNotFound)
			return
		}
		err := json.NewEncoder(w).Encode(map[string]string{
			"public-key": string(key),
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/api/refresh", func(w http.ResponseWriter, r *http.Request) {
		var data Refresh_Request

		json.NewDecoder(r.Body).Decode(&data)

		defer r.Body.Close()

		p, err := readProfile("id", data.User_Id)

		if err != nil {
			http.Error(w, "Could not find profile", http.StatusForbidden)
			return
		}

		if *p.Refresh_Token != data.Refresh_Token {
			json.NewEncoder(w).Encode(Refresh_Response{
				Valid:        false,
				Access_Token: "",
			})
			return
		}

		json.NewEncoder(w).Encode(Refresh_Response{
			Valid:        true,
			Access_Token: generateAccessJWT(p.Id, p.Email, p.Name),
		})

	})

	mux.HandleFunc("/api/reset-password", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		err := json.NewDecoder(r.Body).Decode(&payload);
		defer r.Body.Close()

		profile, err := readProfile("reset_password_token", payload["token"])
		if err != nil {
			json.NewEncoder(w).Encode(Reset_Password_Response{
				Error:   true,
				Message: "Invalid reset token",
			})
			return
		}

		if *profile.Reset_Password_Expiration < time.Now().Unix() {
			json.NewEncoder(w).Encode(Reset_Password_Response{
				Error:   true,
				Message: "Reset token has expired",
			})
			return
		}

		err = updateProfile(profile.Id, "reset_password_expiration", time.Now().Unix());

		if err != nil {
			json.NewEncoder(w).Encode(Reset_Password_Response{
				Error:   true,
				Message: "Failed to reset password",
			})
			return
		}

		passwordhash, err := generatePasswordHash(payload["password"]);

		if err != nil {
			json.NewEncoder(w).Encode(Reset_Password_Response{
				Error:   true,
				Message: "Failed to reset password",
			})
			return
		}

		err = updateProfile(profile.Id, "password", passwordhash)

		if err != nil {
			json.NewEncoder(w).Encode(Reset_Password_Response{
				Error:   true,
				Message: "Failed to reset password",
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]any{
			"error":   false,
			"message": "Password reset successful",
		})
	})

	mux.HandleFunc("/api/reset-password-email", func (w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		err := json.NewDecoder(r.Body).Decode(&payload);
		defer r.Body.Close();

		email := strings.TrimSpace(payload["email"])

		profile, err := readProfile("email", email)

		token, err := generateRandomToken(128)

		err = updateProfile(profile.Id, "reset_password_token", token)
		err = updateProfile(profile.Id, "reset_password_expiration", time.Now().Add(15*time.Minute).Unix())

		if err != nil {
			return
		}

		sendEmail(
			"no-reply@conquerearthmc.com",
			[]string{email},
			"Reset Password\n",
			"Hello! You requested a password reset. Please use the following link to reset your password: https://conquerearthmc.com/#reset-password?token=" + token,
		)
	})

	mux.Handle("/api/user", AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		token := strings.TrimSpace(r.Header.Get("Authorization"))
		token = strings.TrimPrefix(token, "Bearer ")
		if token == "" {
			http.Error(w, "Missing access token", http.StatusUnauthorized)
			return
		}

		payload, ok := verifyAccessJWT(token)
		if !ok {
			http.Error(w, "Invalid access token", http.StatusUnauthorized)
			return
		}

		profile, err := readProfile("id", payload.Id)
		if err != nil {
			http.Error(w, "Could not find profile", http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(map[string]any{
			"id":          profile.Id,
			"name":        profile.Name,
			"email":       profile.Email,
			"tfa_enabled": profile.Tfa_Enabled,
		})
	})))

	mux.Handle("/api/update", AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		token := strings.TrimSpace(r.Header.Get("Authorization"))
		token = strings.TrimPrefix(token, "Bearer ")
		if token == "" {
			http.Error(w, "Missing access token", http.StatusUnauthorized)
			return
		}

		payload, ok := verifyAccessJWT(token)
		if !ok {
			http.Error(w, "Invalid access token", http.StatusUnauthorized)
			return
		}

		profile, err := readProfile("id", payload.Id)
		if err != nil {
			http.Error(w, "Could not find profile", http.StatusNotFound)
			return
		}

		var updates map[string]string
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if name := strings.TrimSpace(updates["name"]); name != "" {
			if err := updateProfile(profile.Id, "name", name); err != nil {
				http.Error(w, "Could not update name", http.StatusInternalServerError)
				return
			}
		}

		if email := strings.TrimSpace(updates["email"]); email != "" {
			if email != profile.Email && emailExists(email) {
				http.Error(w, "Email already exists", http.StatusConflict)
				return
			}
			if err := updateProfile(profile.Id, "email", email); err != nil {
				http.Error(w, "Could not update email", http.StatusInternalServerError)
				return
			}
		}

		if password := strings.TrimSpace(updates["password"]); password != "" {
			hash, err := generatePasswordHash(password)
			if err != nil {
				http.Error(w, "Could not hash password", http.StatusInternalServerError)
				return
			}
			if err := updateProfile(profile.Id, "password_hash", hash); err != nil {
				http.Error(w, "Could not update password", http.StatusInternalServerError)
				return
			}
		}

		json.NewEncoder(w).Encode(map[string]any{
			"error":   false,
			"message": "Profile updated",
		})
	})))

	http.ListenAndServe(":8000", mux)
}
