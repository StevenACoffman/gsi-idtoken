// The flow here follows the documentation page at
// https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
//
// Eli Bendersky [https://eli.thegreenplace.net]
// This code is in the public domain.
package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"google.golang.org/api/idtoken"
	"moul.io/http2curl"
)

// This should be taken from https://console.cloud.google.com/apis/credentials
var GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")

const (
	servingSchema  = "http://"
	servingAddress = "localhost:8030"
	callbackPath   = "/google_callback"
)

var rootHtmlTemplate = template.Must(template.New("root").Parse(`
<!DOCTYPE html>
<html>
<body>
    <script src="https://accounts.google.com/gsi/client" async></script>

		<h1>Welcome to this web app!</h1>
		<p>Let's sign in with Google:</p>
    <div
        id="g_id_onload"
        data-client_id="{{.ClientID}}"
        data-login_uri="{{.CallbackUrl}}">
    </div>
    <div
        class="g_id_signin"
        data-type="standard"
        data-theme="filled_blue"
        data-text="sign_in_with"
        data-shape="rectangular"
				data-width="200"
        data-logo_alignment="left">
    </div>
</body>
</html>
`))

func main() {
	if len(GoogleClientID) == 0 {
		log.Fatal("Set GOOGLE_CLIENT_ID env var")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc(callbackPath, callbackHandler)

	log.Printf("Listening on: %s%s\n", servingSchema, servingAddress)
	log.Panic(http.ListenAndServe(servingAddress, mux))
}

func rootHandler(w http.ResponseWriter, _ *http.Request) {
	err := rootHtmlTemplate.Execute(w, map[string]string{
		"CallbackUrl": servingSchema + servingAddress + callbackPath,
		"ClientID":    GoogleClientID,
	})
	if err != nil {
		panic(err)
	}
}

func callbackHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Got to callback handler!")
	defer req.Body.Close()

	if err := req.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	//TODO(steve): remove all this debug info until next comment
	command, _ := http2curl.GetCurlCommand(req)
	fmt.Println(command.String())
	body, _ := GetReqBody(req)
	fmt.Println()
	fmt.Println("BODY:")
	fmt.Println(body)
	fmt.Println("EOB")
	// The following steps follow
	// https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
	//
	// 1. Verify the CSRF token, which uses the double-submit-cookie pattern and
	//    is added both as a cookie value and post body.
	token, err := req.Cookie("g_csrf_token")
	if err != nil {
		http.Error(w, "token not found", http.StatusBadRequest)
		return
	}

	bodyToken := req.FormValue("g_csrf_token")
	if token.Value != bodyToken {
		http.Error(w, "token mismatch", http.StatusBadRequest)
	}

	// 2. Verify the ID token, which is returned in the `credential` field.
	//    We use the idtoken package for this. `audience` is our client ID.
	ctx := context.Background()
	validator, err := idtoken.NewValidator(ctx)
	if err != nil {
		panic(err)
	}
	// credential string is the OIDC id token jwt value that can be parsed
	credential := req.FormValue("credential")

	payload, err := validator.Validate(ctx, credential, GoogleClientID)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	//TODO(steve): verify that the user is actually in a google group TBD
	// before we set the cookie and proceed
	for key, value := range req.Form {
		fmt.Println("key:", key, "value:", value)
	}

	// 3. Once the token's validity is confirmed, we can use the user identifying
	//    information in the Google ID token.
	for k, v := range payload.Claims {
		fmt.Printf("%v: %v\n", k, v)
	}

	// 4. (steve) set the JWT token value as a new cookie
	c := &http.Cookie{
		Name:     "credential",
		Value:    credential,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   req.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)

	// 5. tells browsers that the response should be exposed to the front-end JavaScript code.
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	//TODO: here is where we redirect to our actual application start page
	// 6. Display meaningful output to the browser
	err = callBackHtmlTemplate.Execute(w, payload.Claims)
	if err != nil {
		panic(err)
	}
}

var callBackHtmlTemplate = template.Must(template.New("root").Parse(`
<!DOCTYPE html>
<html>
<body>
<div>
<ol>
<li>email: {{.email}}</li>
<li>email_verified: {{.email_verified}}</li>
<li>given_name: {{.given_name}}</li>
<li>exp: {{.exp}}</li>
<li>iss: {{.iss}}</li>
<li>azp: {{.azp}}</li>
<li>aud: {{.aud}}</li>
<li>name: {{.name}}</li>
<li>sub: {{.sub}}</li>
<li>hd: {{.hd}}</li>
<li>nbf: {{.nbf}}</li>
<li>picture: {{.picture}}</li>
<li>family_name: {{.family_name}}</li>
<li>iat: {{.iat}}</li>
<li>jti: {{.jti}}</li>
</ol>
    </div>
</body>
</html>
`))

func GetReqBody(req *http.Request) (string, error) {
	if req == nil || req.Body == nil {
		return "", nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	return string(body), nil
}
