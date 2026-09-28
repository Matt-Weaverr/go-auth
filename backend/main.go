package main

func main() {
	initConfig()
	initDB()
	defer db.Close()
	initRouter()
}

