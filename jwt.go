package main

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
)

// jwtSecret is GPM secret (randomly generated) used by
// QRHandler to generate QR code and VerifyHandler API
// to authorize user
var jwtSecret string

// JwtToken represents JWT token generated with /authenticate end-point
type JwtToken struct {
	Token string `json:"token"`
}

// OtpToken represents OTP (One-time Password) token generated after
// success authentication with Google Authenticator
type OtpToken struct {
	User  string `json:"user"`
	Token string `json:"otp"`
}

// SignJwt signs JWT claims with given secret
func SignJwt(claims jwt.MapClaims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// VerifyJwt verifies given token with user's secret and returns JWT claims
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
