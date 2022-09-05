package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"

	_ "golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// Authentication + Encryption key pairs
var sessionStoreKeyPairs = [][]byte{
	[]byte("something-very-secret"),
	nil,
}

var store sessions.Store

var (
	clientID     string
	clientSecret string
	oauthURI     string
	redirectURI  string
	config       *oauth2.Config
)

type User struct {
	Email       string
	DisplayName string
}

func init() {
	// Create file system store with no size limit
	fsStore := sessions.NewFilesystemStore("", sessionStoreKeyPairs...)
	fsStore.MaxLength(0)
	store = fsStore

	gob.Register(&User{})
	gob.Register(&oauth2.Token{})
}

func main() {
	log.SetFlags(log.LstdFlags | log.Llongfile)

	err := godotenv.Load()
	if err != nil {
		log.Fatalf("err loading: %v", err)
	}

	clientID = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	oauthURI = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/", os.Getenv("TENANT_ID"))
	redirectURI = fmt.Sprintf("%s:8080/callback", os.Getenv("REDIRECT_URI"))
	if clientID == "" {
		log.Fatal("AZURE_AD_CLIENT_ID must be set.")
	}

	config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,

		Endpoint: oauth2.Endpoint{
			AuthURL:  oauthURI + "authorize",
			TokenURL: oauthURI + "token",
		},

		Scopes: []string{"User.Read"},
	}

	http.Handle("/", handle(IndexHandler))
	http.Handle("/callback", handle(CallbackHandler))

	// log.Fatal(http.ListenAndServe(":8080", nil))
	log.Fatal(http.ListenAndServeTLS(":8080", "server.crt", "server.key", nil))
}

type handle func(w http.ResponseWriter, req *http.Request) error

func (h handle) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Handler panic: %v", r)
		}
	}()
	if err := h(w, req); err != nil {
		log.Printf("Handler error: %v", err)

		if httpErr, ok := err.(Error); ok {
			http.Error(w, httpErr.Message, httpErr.Code)
		}
	}
}

type Error struct {
	Code    int
	Message string
}

func (e Error) Error() string {
	if e.Message == "" {
		e.Message = http.StatusText(e.Code)
	}
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func IndexHandler(w http.ResponseWriter, req *http.Request) error {
	session, _ := store.Get(req, "session")

	var token *oauth2.Token
	if req.FormValue("logout") != "" {
		session.Values["token"] = nil
		sessions.Save(req, w)
	} else {
		if v, ok := session.Values["token"]; ok {
			token = v.(*oauth2.Token)
		}
	}

	var data = struct {
		Token   *oauth2.Token
		AuthURL string
	}{
		Token:   token,
		AuthURL: config.AuthCodeURL(SessionState(session), oauth2.AccessTypeOnline),
	}

	return indexTempl.Execute(w, &data)
}

var indexTempl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html>
  <head>
    <title>Azure AD OAuth2 Example</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-gH2yIJqKdNHPEq0n4Mqa/HGKIhSkIHeL5AyhkYV8i59U5AR6csBvApHHNl/vI1Bx" crossorigin="anonymous">
  </head>
  <body class="container-fluid">
    <div class="row">
      <div class="col-xs-8">
        <h1>Azure AD OAuth2 Example</h1>
{{with .Token}}
        <h2 id="displayName"></h2>
		<hr>
		<div id="accessToken"></div>
		<hr>
		<pre><code id="jwtContent"></code></pre>
        <a href="/?logout=true">Logout</a>
{{else}}
        <a href="{{$.AuthURL}}">Login</a>
{{end}}
      </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>
    <script>
{{with .Token}}
      var token = {{.}};

      $.ajax({
        url: 'https://graph.windows.net/me?api-version=1.6',
        dataType: 'json',
        success: function(data, status) {
			$('#displayName').text('Welcome [ ' + data.displayName + ' ]');
			$('#accessToken').text('Access Token: ' + token.access_token);
			var base64Url = token.access_token.split('.')[1];
			var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
			var jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
				return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
			}).join(''));
			console.log("data:", data);
			console.log("token:", token);
			console.log("jwt:", JSON.parse(jsonPayload));
			var jwt = JSON.parse(jsonPayload)
			$('#jwtContent').text(JSON.stringify(jwt, undefined, 2));
        },
        beforeSend: function(xhr, settings) {
          xhr.setRequestHeader('Authorization', 'Bearer ' + token.access_token);
        }
      });
{{end}}
    </script>
  </body>
</html>
`))

func CallbackHandler(w http.ResponseWriter, req *http.Request) error {
	session, _ := store.Get(req, "session")

	if req.FormValue("state") != SessionState(session) {
		return Error{http.StatusBadRequest, "invalid callback state"}
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", req.FormValue("code"))
	form.Set("redirect_uri", redirectURI)
	form.Set("resource", "https://graph.windows.net")

	tokenReq, err := http.NewRequest(http.MethodPost, config.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("error creating token request: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		return fmt.Errorf("error performing token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("token response was %s", resp.Status)
	}

	var token oauth2.Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("error decoding JSON response: %v", err)
	}

	session.Values["token"] = &token
	if err := sessions.Save(req, w); err != nil {
		return fmt.Errorf("error saving session: %v", err)
	}

	http.Redirect(w, req, "/", http.StatusFound)
	return nil
}

func SessionState(session *sessions.Session) string {
	return base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte(session.ID)))
}

func dump(v interface{}) {
	spew.Dump(v)
}
