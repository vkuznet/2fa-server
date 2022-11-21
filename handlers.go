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
	"time"

	"github.com/dchest/captcha"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgryski/dgoogauth"
	"github.com/gorilla/context"
)

// we embed few html pages directly into server
// but for advanced usage users should switch to templates

//go:embed "static/tmpl/top.tmpl"
var topHTML string

//go:embed "static/tmpl/bottom.tmpl"
var bottomHTML string

// AuthHandler authenticate user via POST HTTP request
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// parse form parameters
	var user string
	if err := r.ParseForm(); err == nil {
		user = r.FormValue("user")
	}

	secret := findUserSecret(user)
	if secret == "" {
		err := errors.New("Non existing user, please use /qr end-point to initialize and get QR code")
		json.NewEncoder(w).Encode(err)
		return
	}
	// TODO: may be use userData := jwt.MapClaims{}
	//     userData := make(map[string]interface{})
	//     userData["username"] = user
	//     userData["password"] = secret
	//     userData["authorized"] = false
	mapClaims := jwt.MapClaims{}
	mapClaims["username"] = user
	mapClaims["authorized"] = false
	mapClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()

	// for verification we can use either user's secret
	// or server secret
	// in latter case it should be global and available to all APIs
	//     tokenString, err := SignJwt(userData, secret)
	tokenString, err := SignJwt(mapClaims, secret)
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
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// this API expect JSON OtpToken payload
	var otpToken OtpToken
	err := json.NewDecoder(r.Body).Decode(&otpToken)
	if err != nil {
		log.Println("error", err)
		json.NewEncoder(w).Encode(err)
		return
	}
	if Config.Verbose > 0 {
		log.Println("otp token", otpToken)
	}
	user := otpToken.User
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

// UserHandler handles sign-up HTTP requests
func UserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// parse form parameters
	var user, email, password, signup string
	err := r.ParseForm()
	if err == nil {
		user = r.FormValue("user")
		email = r.FormValue("email")
		password = r.FormValue("password")
		signup = r.FormValue("signup")
	} else {
		log.Println("unable to parse user form data", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	passwordHash, err := getPasswordHash(password)
	if err != nil {
		log.Println("unable to get password hash", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// check if user provide the captcha
	if !captcha.VerifyString(r.FormValue("captchaId"), r.FormValue("captchaSolution")) {
		tmplData := make(TmplRecord)
		tmplData["Message"] = "Wrong captcha match, robots are not allowed"
		page := tmplPage("error.tmpl", tmplData)
		w.Write([]byte(page))
		return
	}

	// check if we use signup or signin form
	if signup == "signup" {
		log.Println("sign up form")
		// check if user exists, otherwise create new user entry in DB
		if !userExist(user, passwordHash) {
			addUser(user, passwordHash, email, "")
		}
	} else {
		log.Println("sign in form")
		if !userExist(user, passwordHash) {
			tmplData := make(TmplRecord)
			tmplData["Message"] = "Wrong password or user does not exist"
			page := tmplPage("error.tmpl", tmplData)
			w.Write([]byte(page))
			return
		}
	}

	// redirect request to qrcode end-point
	if Config.Verbose > 0 {
		log.Printf("redirect %+v", r)
	}
	// to preserve the same HTTP method we should use
	// 307 StatusTemporaryRedirect code
	// https://softwareengineering.stackexchange.com/questions/99894/why-doesnt-http-have-post-redirect
	http.Redirect(w, r, "/qrcode", http.StatusTemporaryRedirect)
}

// QRHandler represents handler for /qr end-point to present our QR code
// to the client
func QRHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("call QRHandler %+v", r)
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// parse form parameters
	var user string
	err := r.ParseForm()
	if err == nil {
		user = r.FormValue("user")
	} else {
		log.Println("unable to parse form data", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// check if our user exists in DB
	if !userExist(user, "do not check") {
		msg := fmt.Sprintf("Unknown user %s", user)
		w.Write([]byte(msg))
		return
	}

	// proceed and either create or retrieve QR code for our user
	udir := fmt.Sprintf("static/data/%s", user)
	qrImgFile := fmt.Sprintf("%s/QRImage.png", udir)
	err = os.MkdirAll(udir, 0755)
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
		randomStr := randStr(10, "alphanum")

		// For Google Authenticator purpose
		// for more details see
		// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
		secret := base32.StdEncoding.EncodeToString([]byte(randomStr))
		jwtSecret = secret

		// update user secret in DB
		updateUser(user, jwtSecret)
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
	tmplData := make(TmplRecord)
	tmplData["User"] = user
	tmplData["ImageFile"] = qrImgFile
	page := tmplPage("qrcode.tmpl", tmplData)
	w.Write([]byte(page))
}

// helper function to parse given template and return HTML page
func tmplPage(tmpl string, tmplData TmplRecord) string {
	if tmplData == nil {
		tmplData = make(TmplRecord)
	}
	var templates Templates
	page := templates.Tmpl(Config.Templates, tmpl, tmplData)
	return topHTML + page + bottomHTML
}

// HomeHandler handles home page requests
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	tmplData := make(TmplRecord)
	captchaStr := captcha.New()
	tmplData["CaptchaId"] = captchaStr
	page := tmplPage("index.tmpl", tmplData)
	w.Write([]byte(page))
}

// SignUpHandler handles sign-up page requests
func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	tmplData := make(TmplRecord)
	captchaStr := captcha.New()
	tmplData["CaptchaId"] = captchaStr
	page := tmplPage("signup.tmpl", tmplData)
	w.Write([]byte(page))
}
