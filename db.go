package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// User represents our user attributes
type User struct {
	gorm.Model
	Name   string
	Secret string
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

func addUser(name, secret string) {
	DB.Create(&User{Name: name, Secret: secret})
}

func findUserSecret(name string) string {
	var user User
	DB.First(&user, "name = ?", name) // find product with user name
	return user.Secret
}
