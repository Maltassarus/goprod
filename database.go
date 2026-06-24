package main

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func InitDB() error {
	var err error
	db, err = sql.Open("sqlite3", "./secure_service.db")
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	createTableSQL := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	createIndexSQL := `
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`

	_, err = db.Exec(createIndexSQL)
	if err != nil {
		return fmt.Errorf("failed to create indexes: %v", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	return nil
}

func CloseDB() {
	if db != nil {
		db.Close()
	}
}

func CreateUser(email, username, passwordHash string) (*User, error) {
	query := `INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id, created_at`

	var user User
	user.Email = email
	user.Username = username
	user.PasswordHash = passwordHash

	err := db.QueryRow(query, email, username, passwordHash).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	return &user, nil
}

func GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, email, username, password_hash, created_at FROM users WHERE email = $1`

	var user User
	err := db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %v", err)
	}

	return &user, nil
}

func GetUserByID(id int) (*User, error) {
	query := `SELECT id, email, username, password_hash, created_at FROM users WHERE id = $1`

	var user User
	err := db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %v", err)
	}

	return &user, nil
}

func UserExistsByEmail(email string) (bool, error) {
	query := `SELECT COUNT(*) FROM users WHERE email = $1`

	var count int
	err := db.QueryRow(query, email).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %v", err)
	}

	return count > 0, nil
}
