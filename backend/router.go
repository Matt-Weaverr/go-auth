package main

import (
	"encoding/json"
	"net/http"
)

type AuthResponse struct {
	Tfa bool `json:"tfa"`
	Refresh_Token string `json:"refresh-token"`
	Access_Token string `json:"access-token"`
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

	w.Header().Set("Content-Type", "application/json")

	switch status {
	case -1, 1:
		err := json.NewEncoder(w).Encode(AuthResponse{
			Tfa: false,
			Refresh_Token: "",
			Access_Token: "",
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
			Refresh_Token: "",
			Access_Token: "",
			Message: ""})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case 0:
		err := json.NewEncoder(w).Encode(AuthResponse{
			Tfa: false,
			Error: false,
			Refresh_Token: refreshtoken,
			Access_Token: accesstoken,
			Message: "Failed to login. Please try again later"})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	default:
		err := json.NewEncoder(w).Encode(AuthResponse{
			Tfa: false,
			Error: true,
			Refresh_Token: "",
			Access_Token: "",
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
				Refresh_Token: "",
				Access_Token: "",
				Message: "Email already exists"})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		case 0:
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa: false,
				Error: false,
				Refresh_Token: "",
				Access_Token: "",
				Message: ""})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		default:
			err := json.NewEncoder(w).Encode(AuthResponse{
				Tfa: false,
				Error: true,
				Refresh_Token: "",
				Access_Token: "",
				Message: "Failed to create new user. Please try again later"})

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}


		}

	})

	mux.HandleFunc("/enable-tfa", func(w http.ResponseWriter, r *http.Request) {
		
	})

	mux.HandleFunc("/verify-tfa", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	})

	mux.HandleFunc("/public-key", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	})

	mux.HandleFunc("/reset-password", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	})

	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	})

	mux.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	})

	http.ListenAndServe(":8000", mux)
}