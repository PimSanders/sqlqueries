package sqlqueries

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"

	_ "github.com/go-sql-driver/mysql"
)

func getEnvVariables(key string) string {
	file, err := os.Open(".env")
	defer file.Close()
	if err != nil {
		fmt.Println("No .env file found, creating a new one...")
		envfile := "DB_USERNAME=\nDB_PASSWORD=\nDB_HOSTNAME=\nDB_TABLENAME="
		os.Create(".env")
		ioutil.WriteFile(".env", []byte(envfile), 0644)
		fmt.Println("Done! Don't forget to update the .env file before running again!")
		os.Exit(0)
		return ""
	} else {
		err = godotenv.Load(".env")
		if err != nil {
			panic(err)
		}
		if os.Getenv(key) == "" {
			fmt.Println("Empty env found, please edit the .env file")
			os.Exit(0)
		}
		return os.Getenv(key)
	}
}

func hash(username string, password string) (hash string) {
	bytes := []byte(username + password)
	hasher := sha1.New()
	hasher.Write(bytes)
	hash = hex.EncodeToString((hasher.Sum(nil)))
	return hash
}

func SqlConnect() (db *sql.DB) {
	usernameSQL := getEnvVariables("DB_USERNAME")
	passwordSQL := getEnvVariables("DB_PASSWORD")
	hostnameSQL := getEnvVariables("DB_HOSTNAME")
	tablenameSQL := getEnvVariables("DB_TABLENAME")
	db, err := sql.Open("mysql", usernameSQL+":"+passwordSQL+"@tcp("+hostnameSQL+")/"+tablenameSQL)
	if err != nil {
		panic(err)
	}
	return db
}

func SqlRegister(db *sql.DB, username string, hash string, email string) (allowed bool) {
	insertQuery := "INSERT INTO `users` (Username, Email, Authentication) VALUES (?, ?, ?)"
	insert, err := db.Query(insertQuery, username, email, hash)
	defer insert.Close()
	if err != nil {
		return false
	} else {
		return true
	}
}

func SqlLogin(db *sql.DB, username string, hashed string) (allowed bool) {
	loginQuery := "SELECT Authentication FROM `users` WHERE Username = ?"
	login, err := db.Query(loginQuery, username)
	defer login.Close()
	if err != nil {
		panic(err)
	}
	login.Next()

	var passwordCheck string
	login.Scan(&passwordCheck)

	if hashed == passwordCheck {
		fmt.Println("You are in da mainframe")
		return true
	} else {
		fmt.Println("Authentication error")
		return false
	}
}

func SqlCreateToken(db *sql.DB, username string, hashed string) (allowed bool) {
	createTokenQuery := "UPDATE `users` SET Token = ? WHERE Username = ?"
	rand.Seed(time.Now().UnixNano())
	random := strconv.Itoa(rand.Intn(1000))
	token, err := db.Query(createTokenQuery, hash(hashed, random), username)
	defer token.Close()
	if err != nil {
		return false
	} else {
		return true
	}
}

func SqlDeleteToken(db *sql.DB, username string) (allowed bool) {
	deleteTokenQuery := "UPDATE `users` SET Token = NULL WHERE Username = ?"
	delete, err := db.Query(deleteTokenQuery, username)
	defer delete.Close()
	if err != nil {
		return false
	} else {
		return true
	}
}

func SqlGetToken(db *sql.DB, username string) (allowed bool, tokenString string) {
	getTokenQuery := "SELECT Token FROM `users` WHERE Username = ?"
	token, err := db.Query(getTokenQuery, username)
	defer token.Close()
	if err != nil {
		return false, ""
	} else {
		token.Next()

		var tokenString string
		token.Scan(&tokenString)

		if tokenString == "" {
			return false, tokenString
		} else {
			return true, tokenString
		}
	}
}
