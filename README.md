Go based HTTP server with 2FA based on OTP (One-Time Password) manager like
Google Authenticator, etc.

The server contains the following end-points:
- `/authenticate` to authenticate user and return a valid JWT token via HTTP
  POST request
- `/verify` performs OTP authentication with OTP provider (Google
  Authenticator) and return a valid OTP token 
- `/api` provides authorized user access to protected data

You should install [Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en_US&gl=US) or similar OTP authenticator
on your smart phone.

To build and run server just do the following:
```
# build server code
go build

# run server, by default it runs on port 12345 and use static area
./2fa-server

# to customize your server create JSON configuration file
cat > server.json << EOF
{"port":12345, "static": "/my/path/static"}
EOF
# and now you can run it as following
./2fa-server -config server.json
```
The server stores user data into SQLite DB (basically user's name/secret pairs)
and generate QR code image file(s) in user's static area.

The data flow can be represented as following:
```
# Step 1: install Google Authenticator on your phone

# Step 2: visit our server to get QR code for specific user=UserName
# here code should be imporved to provide user's registration, so far
# any user name is accepted, please change UserName to whatever you like
http://localhost:12345/qr?user=UserName

# Step 3: scan QR code and open URL. It will add new entry into Google Authenticator
# now we are ready to use it with our app

# Step 4: get token
curl -X POST "http://localhost:12345/authenticate?user=UserName"
# it returns server token in JSON format
{"token":"eyJhb..."}

# Step 5: now visit Google Authenticator to obtain new code

# Step 6: authenticate with our server using OTP (One-Time Password) code
# obtained from a previous step
curl -X POST -H "Authorization: Bearer $token" -H "Content-Type: application/json" "http://localhost:12345/verify?user=UserName" -d '{"otp":"383878"}'
# it returns new token from otp secure code generated by Google Authenticator
"eyJhbG..."

# Step 7: call protected API using new OTP token
otpToken="eyJhbG..."
curl -H "Authorization: Bearer $otpToken" "http://localhost:12345/api?user=UserName"
# if everything is fine you'll see the following data with proper password for the user
{"authorized":true,"password":"XXXYYYZZ","username":"UserName"}
```

### References
- [GoLang server with 2FA](https://www.thepolyglotdeveloper.com/2017/05/add-two-factor-authentication-golang-restful-api)
- [GoLang server with JWT](https://www.thepolyglotdeveloper.com/2017/03/authenticate-a-golang-api-with-json-web-tokens)
- [GoLang with Google Auth App](https://www.socketloop.com/tutorials/golang-verify-token-from-google-authenticator-app)
- [sec51 twofactor](https://github.com/sec51/twofactor)
- [go-guardian](github.com/shaj13/go-guardian)
- [Writing auth app with go-guardian](https://medium.com/@hajsanad/writing-scalable-authentication-in-golang-using-go-guardian-83691219a73a)

