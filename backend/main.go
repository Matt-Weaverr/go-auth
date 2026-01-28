package main

func main() {
	initDB()
	defer db.Close()
	initRouter()
}

