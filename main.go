package main

// Author: Valentin Kuznetsov <vkuznet [AT] gmain [DOT] com>
//
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
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgryski/dgoogauth"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"golang.org/x/exp/errors"

	// clone of "code.google.com/p/rsc/qr" which no longer available
	"github.com/vkuznet/rsc/qr"

	// imaging library
	"github.com/disintegration/imaging"
)

// JwtToken represents JWT token generated with /authenticate end-point
type JwtToken struct {
	Token string `json:"token"`
}

// OtpToken represents OTP (One-time Password) token generated after
// success authentication with Google Authenticator
type OtpToken struct {
	Token string `json:"otp"`
}

// SignJwt signs JWT claims with given secret
func SignJwt(claims jwt.MapClaims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// VerifyJwr verifies given token with user's secret and returns JWT claims
func VerifyJwt(token string, secret string) (map[string]interface{}, error) {
	jwToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !jwToken.Valid {
		return nil, fmt.Errorf("Invalid authorization token")
	}
	return jwToken.Claims.(jwt.MapClaims), nil
}

// GetBearerToken returns token from
// HTTP Header "Authorization: Bearer <token>"
func GetBearerToken(header string) (string, error) {
	if header == "" {
		return "", fmt.Errorf("An authorization header is required")
	}
	token := strings.Split(header, " ")
	if Config.Verbose > 0 {
		log.Println("GetBearerToken", token)
	}
	if len(token) != 2 {
		return "", fmt.Errorf("Malformed bearer token")
	}
	return token[1], nil
}

// ValidateMiddleware provides authentication of user credentials
func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		bearerToken, err := GetBearerToken(r.Header.Get("authorization"))
		if err != nil {
			json.NewEncoder(w).Encode(err)
			return
		}
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

func CreateTokenEndpoint(w http.ResponseWriter, r *http.Request) {
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
	mockUser := make(map[string]interface{})
	mockUser["username"] = user
	mockUser["password"] = secret
	mockUser["authorized"] = false
	tokenString, err := SignJwt(mockUser, secret)
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	decoded := context.Get(r, "decoded")
	json.NewEncoder(w).Encode(decoded)
}

// gpmSecret is GPM secret (randomly generated) used by
// QRHandler to generate QR code and VerifyOtpEndpoint API
// to authorize user
var gpmSecret string

// VerifyOtpEndpoint authorizes user based on provided token
// and OTP code
func VerifyOtpEndpoint(w http.ResponseWriter, r *http.Request) {

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

	bearerToken, err := GetBearerToken(r.Header.Get("authorization"))
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
	jwToken, _ := SignJwt(decodedToken, secret)
	json.NewEncoder(w).Encode(jwToken)
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

// helper function to check if file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
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
	udir := fmt.Sprintf("static/%s", user)
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
		gpmSecret = secret

		// store user code/secret to DB
		addUser(user, gpmSecret)
	} else {
		if Config.Verbose > 0 {
			log.Println("read user secret from DB")
		}
		gpmSecret = userSecret
	}

	// authentication link.
	// for more details see
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	authLink := fmt.Sprintf("otpauth://totp/GPM:%s?secret=%s&issuer=GPM", user, gpmSecret)

	// generate QR image
	// Remember to clean up the file afterwards
	//     defer os.Remove(qrImgFile)
	err = generateQRImage(authLink, qrImgFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// generate page content
	content := fmt.Sprintf("<html><body><h1>QR code for : %s</h1><img src='/%s'>", user, qrImgFile)
	w.Write([]byte(content))
}

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

func main() {
	var config string
	flag.StringVar(&config, "config", "", "config file")
	flag.Parse()

	// read configuration
	parseConfig(config)

	log.Printf("Server configuration %+v", Config)

	if Config.Verbose > 0 {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	// setup our DB backend
	setupDB(Config.DBFile)

	router := mux.NewRouter()
	fmt.Println("Starting the application...")
	router.HandleFunc("/authenticate", CreateTokenEndpoint).Methods("POST")
	router.HandleFunc("/verify-otp", VerifyOtpEndpoint).Methods("POST")
	router.HandleFunc("/protected", ValidateMiddleware(ProtectedEndpoint)).Methods("GET")

	// this is for displaying the QR code on /qr end point
	// and static area which holds user's images
	router.HandleFunc("/qr", QRHandler).Methods("GET")
	fileServer := http.StripPrefix("/static/", http.FileServer(http.Dir("./static")))
	router.PathPrefix("/static/{user:[0-9a-zA-Z-]+}/{file:[0-9a-zA-Z-\\.]+}").Handler(fileServer)

	addr := fmt.Sprintf(":%d", Config.Port)
	log.Fatal(http.ListenAndServe(addr, router))
}
