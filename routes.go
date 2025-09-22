package main

import (
	"fmt"
	"net/http"
	"github.com/gorilla/mux"
)


func router() {
	r := mux.NewRouter()

	r.HandleFunc("/")
}