package main

import "fmt"

func main() {
	initDB()
	defer db.Close()
}