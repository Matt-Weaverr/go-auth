package main

import (
	"encoding/json"
	"net/http"
	"time"
)

const ALLOWED_ORIGIN = "*"

type AuthResponse struct {
	Tfa_Required bool `json:"tfa-required"`
	Pre_Auth_Token string `json:"pre-auth-token"`
	Authorization_Code string `json:"authorization-code"`
	Error bool `json:"error"`
	Message string `json:"message"`
}

type NewUser struct {
	Email string `json:"email"`
	Name string `json:"name"`
	Password string `json:"password"`
}

type User struct {
	Email string `json:"email"`
	Password string `json:"password"`
	Dfp string `json:"dfp"`
}

type Tfa struct {
	Otp int `json:"otp"`
	Token string `json:"token"`
}

type Tfa_Response struct {
	Error bool `json:"error"`
	Message string `json:"message"`
}

type Refresh_Request struct {
	User_Id int `json:"user-id"`
	Refresh_Token string `json:"refresh-token"`
}

type Refresh_Response struct {
	Valid bool `json:"valid"`
	Access_Token string `json:"access-token"`
}

func initRouter() {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
	
		var u User

		err := json.NewDecoder(r.Body).Decode(&u)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		status, refreshtoken, accesstoken, preauthtoken := login(u.Email, u.Password, u.Dfp)
		/*
		Login status codes
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
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa_Required: false,
				Pre_Auth_Token: "",
				Authorization_Code: "",
				Error: true,
				Message: "Email or password is incorrect"})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case 4:
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa_Required: true,
				Pre_Auth_Token: preauthtoken,
				Error: false,
				Authorization_Code: "",
				Message: ""})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case 0:
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa_Required: false,
				Pre_Auth_Token: "",
				Error: false,
				Authorization_Code: authorization_code,
				Message: ""})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			//this is used to authenticate on the edit user page
			cookie := http.Cookie{
				Name:     "refresh-token",
				Value:    refreshtoken,
				Expires:  time.Now().Add(24 * time.Hour),
				Path:     "/",                           
				HttpOnly: true,                           
				Secure:   false,                          
				SameSite: http.SameSiteLaxMode,          
			}	

			http.SetCookie(w, &cookie)

		default:
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa_Required: false,
				Error: true,
				Authorization_Code: "",
				Message: "Failed to login. Please try again later"})

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
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {

		var u NewUser
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
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa_Required: false,
				Error: true,
				Authorization_Code: "",
				Message: "Email already exists"})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case 0:
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa_Required: false,
				Error: false,
				Authorization_Code: "",
				Message: ""})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		default:
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa_Required: false,
				Error: true,
				Authorization_Code: "",
				Message: "Failed to create new user. Please try again later"})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}


		}

	})

	mux.HandleFunc("/verify-tfa", func(w http.ResponseWriter, r *http.Request) {

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
			json.NewEncoder(w).Encode(map[string]interface{
				"error": true,
				"message": "Invalid verification code",
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{
			"error": false,
			"message": "",
		})

	})

	mux.HandleFunc("/authorization", func(w http.ResponseWriter, r *http.Request) {

		query := r.URL.Query()

		code := query.Get("code")

		status, refresh_token, access_token := getTokens(code)
		
		if status == -1 {
				http.Error(w, "Failed to find codes", http.StatusNotFound)
				return
			}
		
		err := json.NewEncoder(w).Encode(map[string]string{
			"refresh-token": refresh_token,
			"access-token": access_token,
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

				
	})

	mux.HandleFunc("/public-key", func(w http.ResponseWriter, r *http.Request) {

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

	mux.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		var data Refresh_Request 

		json.NewDecoder(r).Decode(&data)

		p, err := readProfile("id", data.User_Id)

		if err != nil {
			http.Error(w, "Could not find profile", http.StatusForbidden)
			return
		}

		if p.Refresh_Token != data.Refresh_Token {
			json.NewEncoder(w).Encode(Refresh_Response{
				Valid: false,
				Access_Token: "" })
			return
		}

		json.NewEncoder(w).Encode(Refresh_Response{
			Valid: true,
			Access_Token: generateAccessJWT(p.Id, p.Email, p.Name)
		})


	}

	mux.HandleFunc("/reset-password", func(w http.ResponseWriter, r *http.Request) {
		//
	})

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		//
	})

	mux.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		//
	})

	http.ListenAndServe(":8000", corsMiddleware(mux))
}
