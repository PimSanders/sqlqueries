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

//Gets the env variable from the .env file, if none exist it will create one.
func getEnvVariables(envname string) string {
	if _, err := os.Stat(".env"); err != nil {
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
		if os.Getenv(envname) == "" {
			fmt.Println("Empty env found, please edit the .env file")
			os.Exit(0)
		}
		return os.Getenv(envname)
	}
}

//Hashes the username + password into one hash and encodes it.
func hash(username string, password string) (hash string) {
	bytes := []byte(username + password)
	hasher := sha1.New()
	hasher.Write(bytes)
	hash = hex.EncodeToString((hasher.Sum(nil)))
	return hash
}

//Opens a database connection using the configured env's, returns database connection.
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

func sqlCheckIfExists(db *sql.DB, username string, email string) (userExists bool) {
	getUsernameQuery := "SELECT Username FROM `users` WHERE Username = ?"
	usernameSelect, err := db.Query(getUsernameQuery, username)
	defer usernameSelect.Close()
	if err != nil {
		panic(err)
	}
	getEmailQuery := "SELECT Email FROM `users` WHERE Email = ?"
	emailSelect, err := db.Query(getEmailQuery, email)
	defer emailSelect.Close()
	if err != nil {
		panic(err)
	}
	var usernameSelectScan string
	var emailSelectScan string
	usernameSelect.Next()
	emailSelect.Next()
	usernameSelect.Scan(&usernameSelectScan)
	emailSelect.Scan(&emailSelectScan)
	if emailSelectScan == "" && usernameSelectScan == "" {
		return false
	} else {
		return true
	}
}

//Registers the userdata into the database if the username and email are unique.
func SqlRegister(db *sql.DB, username string, password string, email string) (allowRegister bool) {
	if sqlCheckIfExists(db, username, email) {
		return false
	} else {
		insertQuery := "INSERT INTO `users` (Username, Email, Authentication) VALUES (?, ?, ?)"
		insert, err := db.Query(insertQuery, username, email, hash(username, password))
		defer insert.Close()
		if err != nil {
			return false
		} else {
			return true
		}
	}
}

//Attempts to login the user with the username and password.
func SqlLogin(db *sql.DB, username string, password string) (allowLogin bool) {
	loginQuery := "SELECT Authentication FROM `users` WHERE Username = ?"
	login, err := db.Query(loginQuery, username)
	defer login.Close()
	if err != nil {
		return false
	}
	login.Next()

	var passwordCheck string
	login.Scan(&passwordCheck)

	if hash(username, password) == passwordCheck {
		return true
	} else {
		return false
	}
}

//Creates a random token for specified user.
func SqlCreateToken(db *sql.DB, username string) (allowCreateToken bool) {
	createTokenQuery := "UPDATE `users` SET Token = ? WHERE Username = ?"
	rand.Seed(time.Now().UnixNano())
	random := strconv.Itoa(rand.Intn(1000))
	token, err := db.Query(createTokenQuery, hash(username, random), username)
	defer token.Close()
	if err != nil {
		return false
	} else {
		return true
	}
}

//Deletes the token for the user.
func SqlDeleteToken(db *sql.DB, username string) (allowDeleteToken bool) {
	deleteTokenQuery := "UPDATE `users` SET Token = NULL WHERE Username = ?"
	delete, err := db.Query(deleteTokenQuery, username)
	defer delete.Close()
	if err != nil {
		return false
	} else {
		return true
	}
}

//Requests the token for the specified user from the database.
func SqlGetToken(db *sql.DB, username string) (allowGetToken bool, tokenString string) {
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
