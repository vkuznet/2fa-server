package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"image"
	"log"
	"os"
	"strings"

	"golang.org/x/exp/errors"

	// clone of "code.google.com/p/rsc/qr" which no longer available
	"github.com/vkuznet/rsc/qr"

	// imaging library
	"github.com/disintegration/imaging"
)

// helper function to generate QR image file
func generateQRImage(authLink, fname string) error {
	// Encode authLink to QR codes
	// qr.H = 65% redundant level
	// see https://godoc.org/code.google.com/p/rsc/qr#Level
	code, err := qr.Encode(authLink, qr.H)
	if err != nil {
		log.Println("unable to encode auth link", err)
		return err
	}

	imgByte := code.PNG()

	// convert byte to image for saving to file
	img, _, _ := image.Decode(bytes.NewReader(imgByte))

	// TODO: file should be unique for each client
	err = imaging.Save(img, fname)
	if err != nil {
		log.Println("unable to generate QR image file", err)
	}
	return err
}

// getBearerToken returns token from
// HTTP Header "Authorization: Bearer <token>"
func getBearerToken(header string) (string, error) {
	if header == "" {
		return "", fmt.Errorf("An authorization header is required")
	}
	token := strings.Split(header, " ")
	if Config.Verbose > 0 {
		log.Println("getBearerToken", token)
	}
	if len(token) != 2 {
		return "", fmt.Errorf("Malformed bearer token")
	}
	return token[1], nil
}

// helper function to check if file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}

// helper function for random string generation
func randStr(strSize int, randType string) string {
	var dictionary string

	if randType == "alphanum" {
		dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "alpha" {
		dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	}

	if randType == "number" {
		dictionary = "0123456789"
	}

	var bytes = make([]byte, strSize)
	rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}
	return string(bytes)
}
