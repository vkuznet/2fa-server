package main

import (
	_ "embed"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dgryski/dgoogauth"
	"github.com/gorilla/context"
)

// AuthHandler authenticate user via POST HTTP request
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	user := query.Get("user") //user="bla"
	if user == "" {
		w.Write([]byte("Please provide user name"))
		return
	}
	secret := findUserSecret(user)
	if secret == "" {
		err := errors.New("Non existing user, please use /qr end-point to initialize and get QR code")
		json.NewEncoder(w).Encode(err)
		return
	}
	userData := make(map[string]interface{})
	userData["username"] = user
	userData["password"] = secret
	userData["authorized"] = false

	// for verification we can use either user's secret
	// or server secret
	// in latter case it should be global and available to all APIs
	tokenString, err := SignJwt(userData, secret)
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

// ApiHandler represents protected end-point for our server API
// It can be only reached via 2FA method
func ApiHandler(w http.ResponseWriter, r *http.Request) {
	// so far we return content of our HTTP request context
	// but its logic can implement anything
	decoded := context.Get(r, "decoded")
	json.NewEncoder(w).Encode(decoded)
}

// VerifyHandler authorizes user based on provided token
// and OTP code
func VerifyHandler(w http.ResponseWriter, r *http.Request) {

	query := r.URL.Query()
	user := query.Get("user") //user="bla"
	if user == "" {
		w.Write([]byte("Please provide user name"))
		return
	}
	secret := findUserSecret(user)
	if secret == "" {
		err := errors.New("Non existing user, please use /qr end-point to initialize and get QR code")
		json.NewEncoder(w).Encode(err)
		return
	}

	bearerToken, err := getBearerToken(r.Header.Get("authorization"))
	if Config.Verbose > 0 {
		log.Println("verify otp", bearerToken, "error", err)
	}
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}
	decodedToken, err := VerifyJwt(bearerToken, secret)
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}
	otpc := &dgoogauth.OTPConfig{
		Secret:      secret,
		WindowSize:  3,
		HotpCounter: 0,
	}
	if Config.Verbose > 0 {
		log.Printf("otpc %+v", otpc)
	}
	var otpToken OtpToken
	err = json.NewDecoder(r.Body).Decode(&otpToken)
	if err != nil {
		log.Println("error", err)
		json.NewEncoder(w).Encode(err)
		return
	}
	if Config.Verbose > 0 {
		log.Println("otp token", otpToken)
	}
	decodedToken["authorized"], err = otpc.Authenticate(otpToken.Token)
	if err != nil {
		log.Println("error", err)
		json.NewEncoder(w).Encode(err)
		return
	}
	if decodedToken["authorized"] == false {
		json.NewEncoder(w).Encode("Invalid one-time password")
		return
	}
	if Config.Verbose > 0 {
		log.Println("otp authorized", otpToken)
	}
	// for verification we can use either user's secret
	// or server secret
	// in latter case it should be global and available to all APIs
	jwToken, _ := SignJwt(decodedToken, secret)
	json.NewEncoder(w).Encode(jwToken)
}

// QRHandler represents handler for /qr end-point to present our QR code
// to the client
func QRHandler(w http.ResponseWriter, r *http.Request) {

	// this end-points expects that user provide its user name
	query := r.URL.Query()
	user := query.Get("user") //user="bla"
	if user == "" {
		w.Write([]byte("Please provide user name"))
		return
	}
	udir := fmt.Sprintf("%s/%s", Config.StaticDir, user)
	qrImgFile := fmt.Sprintf("%s/QRImage.png", udir)
	err := os.MkdirAll(udir, 0755)
	if err != nil {
		if Config.Verbose > 0 {
			log.Printf("unable to create directory %s, error %v", udir, err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	userSecret := findUserSecret(user)
	showQRCode := false
	if userSecret == "" {
		// no user exists in DB
		if Config.Verbose > 0 {
			log.Println("generate user secret")
		}

		// generate a random string - preferbly 6 or 8 characters
		randomStr := randStr(6, "alphanum")

		// For Google Authenticator purpose
		// for more details see
		// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
		secret := base32.StdEncoding.EncodeToString([]byte(randomStr))
		jwtSecret = secret

		// store user code/secret to DB
		addUser(user, jwtSecret)
		showQRCode = true
	} else {
		if Config.Verbose > 0 {
			log.Println("read user secret from DB")
		}
		jwtSecret = userSecret
	}

	// authentication link.
	// for more details see
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	authLink := fmt.Sprintf("otpauth://totp/GPM:%s?secret=%s&issuer=GPM", user, jwtSecret)

	// generate QR image
	// Remember to clean up the file afterwards
	//     defer os.Remove(qrImgFile)
	err = generateQRImage(authLink, qrImgFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// generate page content
	var content string
	if showQRCode {
		content = fmt.Sprintf("<html><body><h1>QR code for: %s</h1><img src='/%s'></body></html>", user, qrImgFile)
	} else {
		content = fmt.Sprintf("<html><body>QR code for %s is already generated</body></html>", user)
	}
	w.Write([]byte(content))
}

//go:embed "static/index.html"
var homePage string

// HomeHandler handles home page requests
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(homePage))
}

//go:embed "static/signup.html"
var signPage string

// SignUpHandler handles sign-up page requests
func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(signPage))
}
