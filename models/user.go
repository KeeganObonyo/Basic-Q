package models

import (
	"fmt"
	"time"
)

type User struct {
	Id        int
	Uuid      string
	Name      string
	Email     string
	Password  string
	Dateofbirth string
	CreatedAt time.Time
}

// Create a new user, save user info into the database
func (user *User) Create() (err error) {
	// Postgres does not automatically return the last insert id, because it would be wrong to assume
	// you're always using a sequence.You need to use the RETURNING keyword in your insert to get this
	// information from postgres.
	statement := "insert into users (uuid, name, email, password, dateofbirth, created_at) values ($1, $2, $3, $4, $5, $6) returning id, uuid, created_at"
	stmt, err := Db.Prepare(statement)
	if err != nil {
		fmt.Println("Created")
		return
	}
	defer stmt.Close()

	// use QueryRow to return a row and scan the returned id into the User struct
	err = stmt.QueryRow(createUUID(), user.Name, user.Email, Encrypt(user.Password), user.Dateofbirth, time.Now()).Scan(&user.Id, &user.Uuid, &user.CreatedAt)
	return
}

// Delete user from database
func (user *User) Delete() (err error) {
	statement := "delete from users where id = $1"
	stmt, err := Db.Prepare(statement)
	if err != nil {
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.Id)
	return
}

// Update user information in the database
func (user *User) Update() (err error) {
	statement := "update users set name = $2, email = $3 where id = $1"
	stmt, err := Db.Prepare(statement)
	if err != nil {
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(user.Id, user.Name, user.Email)
	return
}

// Get all users in the database and returns it
func Users() (users []User, err error) {
	rows, err := Db.Query("SELECT id, uuid, name, email, password, dateofbirth, created_at FROM users")
	if err != nil {
		return
	}
	for rows.Next() {
		user := User{}
		if err = rows.Scan(&user.Id, &user.Uuid, &user.Name, &user.Email, &user.Password, &user.Dateofbirth, &user.CreatedAt); err != nil {
			return
		}
		users = append(users, user)
	}
	rows.Close()
	return
}

// Get a single user given the email
func UserByEmail(email string) (user User, err error) {
	user = User{}
	err = Db.QueryRow("SELECT id, uuid, name, email, password, dateofbirth, created_at FROM users WHERE email = $1", email).
		Scan(&user.Id, &user.Uuid, &user.Name, &user.Email, &user.Password, &user.Dateofbirth, &user.CreatedAt)
	return
}

// Get a single user given the UUID
func UserByUUID(uuid string) (user User, err error) {
	user = User{}
	err = Db.QueryRow("SELECT id, uuid, name, email, password, dateofbirth, created_at FROM users WHERE uuid = $1", uuid).
		Scan(&user.Id, &user.Uuid, &user.Name, &user.Email, &user.Password, &user.Dateofbirth, &user.CreatedAt)
	return
}
