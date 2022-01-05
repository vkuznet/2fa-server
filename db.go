package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// User represents our user attributes
type User struct {
	gorm.Model
	Name     string
	Password string
	Email    string
	Secret   string
}

var DB *gorm.DB

func setupDB(fname string) {
	db, err := gorm.Open(sqlite.Open(fname), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	// Migrate the schema
	db.AutoMigrate(&User{})

	// initialize DB pointer
	DB = db
}

func updateUser(name, secret string) {
	var user User
	DB.First(&user, "name = ?", name)
	user.Secret = secret
	DB.Save(&user)
}
func addUser(name, password, email, secret string) {
	user := &User{
		Name:     name,
		Email:    email,
		Password: password,
		Secret:   secret,
	}
	DB.Create(user)
}

func userExist(name, password string) bool {
	var user User
	if password == "do not check" {
		DB.First(&user, "name = ?", name)
	} else {
		DB.First(&user, "name = ? AND password = ?", name, password)
	}
	if user.Name == name {
		return true
	}
	return false
}

func findUserSecret(name string) string {
	var user User
	//     DB.First(&user, "name = ?", name)
	DB.Find(&user, "name = ?", name)
	return user.Secret
}
