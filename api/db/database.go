package db

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func InitDB() {
	var err error
	DB, err = sql.Open("sqlite3", "./waf.db")
	if err != nil {
		panic(err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		password TEXT
	);`
	_, err = DB.Exec(createTable)
	if err != nil {
		panic(err)
	}

	// Ajouter un utilisateur admin par défaut si inexistant
	var count int
	err = DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "admin").Scan(&count)
	if err != nil {
		panic(err)
	}
	if count == 0 {
		_, _ = DB.Exec("INSERT INTO users(username, password) VALUES(?, ?)", "admin", "admin123")
		fmt.Println("Utilisateur admin créé: admin/admin123")
	}
}
