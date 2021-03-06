package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/context"
	"golang.org/x/exp/errors"
)

// ValidateMiddleware provides authentication of user credentials
func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var user string
		if r.Method == "GET" {
			query := r.URL.Query()
			user = query.Get("user") //user="bla"
			if user == "" {
				w.Write([]byte("Please provide user name"))
			}
		} else if r.Method == "POST" {
			var otpToken OtpToken
			err := json.NewDecoder(r.Body).Decode(&otpToken)
			if err != nil {
				log.Println("error", err)
				json.NewEncoder(w).Encode(err)
				return
			}
			user = otpToken.User
		}
		secret := findUserSecret(user)
		if secret == "" {
			err := errors.New("Unable to find user credentials, please obtain proper QR code")
			json.NewEncoder(w).Encode(err)
			return
		}
		bearerToken, err := getBearerToken(r.Header.Get("authorization"))
		if err != nil {
			json.NewEncoder(w).Encode(err)
			return
		}
		// for verification we can use either user's secret
		// or server secret
		// in latter case it should be global and available to all APIs
		decodedToken, err := VerifyJwt(bearerToken, secret)
		if err != nil {
			json.NewEncoder(w).Encode(err)
			return
		}
		if decodedToken["authorized"] == true {
			context.Set(r, "decoded", decodedToken)
			next(w, r)
		} else {
			json.NewEncoder(w).Encode("2FA is required")
		}
	})
}
