package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"

	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

const (
	clientID     = "e2e6fbda-96d5-4305-88c2-7871d931e98a"  //AAD App Client Id
	clientSecret = "q?hwtaQeOHA:Mj[ompvEGcX=3OKF6U45"      //AAD App Client Secret
	tenant       = "3eca6f3f-437a-470d-9c98-872986ee4297"  //Tenant of the AAD App
	redirectURI  = "http://localhost:3011/getAToken"       //Redirect URI to be used by AAD after auth of user. This is user the Auth code is sent
	scope        = "https://graph.microsoft.com/user.read" // ex: https://graph.microsoft.com/mail.read
)

var (
	xOauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     microsoft.AzureADEndpoint(tenant),
		Scopes:       []string{scope},
	}
)

type Server struct {
	user aadUser
}

var server Server

// Auth handler which will redirect to AAD
func authHandler(w http.ResponseWriter, r *http.Request) {
	state := randToken(48)
	authorizationURL := xOauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authorizationURL, 301)
}

type tokenType string

// process the redirection from AAD
func aadAuthHandler(w http.ResponseWriter, r *http.Request) {

	authorizationCode := r.URL.Query().Get("code")

	ck, err := r.Cookie("state")
	if err == nil && (r.URL.Query().Get("state") != ck.Value) {
		_, _ = fmt.Fprintf(w, "Error: State is not the same")
	}

	oAuthToken, err := xOauth2Config.Exchange(context.Background(), authorizationCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := readAADUser(xOauth2Config.Client(context.Background(), oAuthToken))

	// fmt.Fprintln(w, json.NewEncoder(w).Encode(user))
	server.user = user

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func readAADUser(client *http.Client) aadUser {
	req, _ := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me/", nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error while creating client to query graph.microsoft.com for user's token %v", err.Error())
	}

	user := aadUser{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		log.Fatalf("Error while decoding %v", err.Error())
	}
	return user
}

type aadUser struct {
	OdataContext      string      `json:"@odata.context"`
	BusinessPhones    []string    `json:"businessPhones"`
	DisplayName       string      `json:"displayName"`
	GivenName         string      `json:"givenName"`
	JobTitle          string      `json:"jobTitle"`
	Mail              string      `json:"mail"`
	MobilePhone       interface{} `json:"mobilePhone"`
	OfficeLocation    string      `json:"officeLocation"`
	PreferredLanguage interface{} `json:"preferredLanguage"`
	Surname           string      `json:"surname"`
	UserPrincipalName string      `json:"userPrincipalName"`
	ID                string      `json:"id"`
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to testing golang")
	if server.user.DisplayName != "" {
		fmt.Fprintf(w, "\nUser name: %v", server.user.DisplayName)
	}
}

func randToken(n int) string {
	letters := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func main() {
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/getAToken", aadAuthHandler)
	http.HandleFunc("/", homeHandler)
	http.ListenAndServe(":3011", nil)
}
