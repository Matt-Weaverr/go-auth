package main

import (
	"encoding/json"
	"net/http"
)

type AuthResponse struct {
	Tfa bool `json:"tfa"`
	Authorization_Code string `json:"authorization-code"`
	Error bool `json:"error"`
	Message string `json:"message"`
}


func initRouter() {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		email := r.PostFormValue("email")
		password := r.PostFormValue("password")
		dfp := r.PostFormValue("device-fingerprint")

		status, refreshtoken, accesstoken := login(email, password, dfp)
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
			Tfa: false,
			Authorization_Code: "",
			Error: true,
			Message: "Email or password is incorrect"})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case 4:
		err := json.NewEncoder(w).Encode(AuthResponse{
			Tfa: true,
			Error: false,
			Authorization_Code: "",
			Message: ""})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case 0:
		err := json.NewEncoder(w).Encode(AuthResponse{
			Tfa: false,
			Error: false,
			Authorization_Code: authorization_code,
			Message: "Failed to login. Please try again later"})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	default:
		err := json.NewEncoder(w).Encode(AuthResponse{
			Tfa: false,
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
		w.Header().Set("Content-Type", "application/json")

		name := r.PostFormValue("name")
		email := r.PostFormValue("email")
		password := r.PostFormValue("password")

		status := register(name, email, password)

		switch status {
		case -1:
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa: false,
				Error: true,
				Authorization_Code: "",
				Message: "Email already exists"})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case 0:
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa: false,
				Error: false,
				Authorization_Code: "",
				Message: ""})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		default:
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa: false,
				Error: true,
				Authorization_Code: "",
				Message: "Failed to create new user. Please try again later"})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}


		}

	})

	mux.HandleFunc("/enable-tfa", func(w http.ResponseWriter, r *http.Request) {
		//
	})

	mux.HandleFunc("/verify-tfa", func(w http.ResponseWriter, r *http.Request) {
		//
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

		key := loadRSAPublicKeyFromPEM("public-key.pem")

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

	mux.HandleFunc("/reset-password", func(w http.ResponseWriter, r *http.Request) {
		//
	})

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		//
	})

	mux.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		//
	})

	http.ListenAndServe(":8000", mux)
}