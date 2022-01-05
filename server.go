package main

// Author: Valentin Kuznetsov <vkuznet [AT] gmain [DOT] com>
// Server module

// Credits:
// 2fa QR code and server handler to verify 2FA code
// https://www.socketloop.com/tutorials/golang-verify-token-from-google-authenticator-app
// How to generate QR code
// https://socketloop.com/tutorials/golang-how-to-generate-qr-codes
// https://www.socketloop.com/tutorials/golang-generate-qr-codes-for-google-authenticator-app-and-fix-cannot-interpret-qr-code-error

// 2FA authentication code
// https://www.thepolyglotdeveloper.com/2017/05/add-two-factor-authentication-golang-restful-api/
// https://www.thepolyglotdeveloper.com/2017/03/authenticate-a-golang-api-with-json-web-tokens/
// https://www.thepolyglotdeveloper.com/2017/05/implement-2fa-time-based-one-time-passwords-node-js-api/

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	// clone of "code.google.com/p/rsc/qr" which no longer available
	// imaging library
)

// HomeHandler represents server home page
// server represents our HTTP server
// TODO: add HTTPs when Config will provide server certs
func server() {
	// setup our DB backend
	setupDB(Config.DBFile)

	router := mux.NewRouter()
	router.StrictSlash(true) // to allow /route and /route/ end-points

	router.HandleFunc("/authenticate", AuthHandler).Methods("POST")
	router.HandleFunc("/verify", VerifyHandler).Methods("POST")
	router.HandleFunc("/api", ValidateMiddleware(ApiHandler)).Methods("GET")

	// this is for displaying the QR code on /qr end point
	// and static area which holds user's images
	router.HandleFunc("/qr", QRHandler).Methods("GET")
	fileServer := http.StripPrefix("/static/", http.FileServer(http.Dir("./static")))
	router.PathPrefix("/static/{user:[0-9a-zA-Z-]+}/{file:[0-9a-zA-Z-\\.]+}").Handler(fileServer)

	// static css content
	router.PathPrefix("/css/{file:[0-9a-zA-Z-\\.]+}").Handler(fileServer)

	router.HandleFunc("/signup", SignUpHandler).Methods("GET")
	router.HandleFunc("/", HomeHandler).Methods("GET")

	addr := fmt.Sprintf(":%d", Config.Port)
	log.Fatal(http.ListenAndServe(addr, router))
}
