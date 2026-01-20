package main

func main() {
	initDB()
	initRouter()
	defer db.Close()
}