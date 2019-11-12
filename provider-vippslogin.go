// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vippslogin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(VippsLogin{})
}

// VippsLogin facilitates logging in using Vipps Login (https://vipps.no)
type VippsLogin struct {
	Root         string `json:"root,omitempty"` // default is current directory
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	RedirectURL  string `json:"redirect_url,omitempty"`
	SigningKey   string `json:"signing_key,omitempty"`

	signingKey []byte
}

// CaddyModule returns the Caddy module information.
func (VippsLogin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.authentication.providers.vipps_login",
		New:  func() caddy.Module { return new(VippsLogin) },
	}
}

// Provision provisions the HTTP basic auth provider.
func (vl *VippsLogin) Provision(ctx caddy.Context) error {
	if vl.Root == "" {
		vl.Root = "{http.vars.root}"
	}

	var err error
	vl.signingKey, err = base64.StdEncoding.DecodeString(vl.SigningKey)
	if err != nil {
		return fmt.Errorf("secret_key is not a base64 string: %w", err)
	}
	if len(vl.signingKey) != sha256.BlockSize {
		return fmt.Errorf("secret_key must be a %d byte long base64 string, was %d", sha256.BlockSize, len(vl.signingKey))
	}
	vl.SigningKey = ""
	return nil
}

type userinfo struct {
	PhoneNumber string `json:"phone_number"`
}

func (vl VippsLogin) isRedirURL(r *http.Request) bool {
	if len(r.FormValue("code")) == 0 {
		return false
	}
	if len(r.FormValue("state")) == 0 {
		return false
	}
	redirURL, err := url.Parse(vl.RedirectURL)
	if err != nil {
		return false
	}
	return strings.TrimLeft(r.URL.Path, "/") == strings.TrimLeft(redirURL.Path, "/")
}

// TODO: Replicate FileServer behaviour when that changes
func (vl VippsLogin) path(r *http.Request) string {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)
	root := repl.ReplaceAll(vl.Root, ".")
	suffix := repl.ReplaceAll(r.URL.Path, "")
	if root == "" {
		root = "."
	}
	return filepath.Join(root, filepath.FromSlash(path.Clean("/"+suffix)))
}

// allowedNumbers returns a slice of all allowed mobile numbers to the current request, and bool true if it's an open page
func (vl VippsLogin) allowedNumbers(r *http.Request) ([]string, bool) {
	accessFile := filepath.Join(vl.path(r), ".vipps-login")
	file, err := os.Lstat(vl.path(r))
	if err != nil {
		return []string{}, true
	}
	if !file.Mode().IsDir() {
		accessFile = filepath.Join(filepath.Dir(vl.path(r)), ".vipps-login")
	}
	data, err := ioutil.ReadFile(accessFile)
	if err != nil {
		return []string{}, true
	}
	return strings.Split(string(data), "\n"), false
}

func (vl VippsLogin) handleRedir(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	conf := vl.oauth2conf()
	code := r.FormValue("code")
	tok, err := conf.Exchange(r.Context(), code)
	if err != nil {
		return caddyauth.User{}, false, err
	}

	client := conf.Client(r.Context(), tok)
	resp, err := client.Get("https://api.vipps.no/access-management-1.0/access/userinfo")
	if err != nil {
		return caddyauth.User{}, false, err
	}
	if resp.StatusCode != http.StatusOK {
		return caddyauth.User{}, false, nil
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return caddyauth.User{}, false, err
	}

	ui := userinfo{}
	err = json.Unmarshal(body, &ui)
	if err != nil {
		return caddyauth.User{}, false, err
	}

	phoneNumberBytes := []byte(ui.PhoneNumber)
	phoneBase64 := base64.StdEncoding.EncodeToString(phoneNumberBytes)
	mac := hmac.New(sha256.New, vl.signingKey)
	mac.Write(phoneNumberBytes)
	computedMAC := mac.Sum(nil)
	macBase64 := base64.StdEncoding.EncodeToString(computedMAC)
	cookieValue := phoneBase64 + "." + macBase64

	http.SetCookie(w, &http.Cookie{
		Name:    "vipps-login-user",
		Value:   cookieValue,
		Expires: time.Now().AddDate(0, 0, 1),
	})

	state, err := base64.StdEncoding.DecodeString(r.FormValue("state"))
	if err != nil {
		return caddyauth.User{}, false, err
	}
	target := strings.TrimLeft(string(state), "URL: ")
	http.Redirect(w, r, target, http.StatusSeeOther)
	return caddyauth.User{ID: ui.PhoneNumber}, true, nil
}

// Authenticate validates the user credentials in request and returns the user, if valid.
func (vl VippsLogin) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	if vl.isRedirURL(r) {
		return vl.handleRedir(w, r)
	}
	numbers, open := vl.allowedNumbers(r)
	if open {
		return caddyauth.User{}, true, nil
	}
	cookie, err := r.Cookie("vipps-login-user")
	if err == http.ErrNoCookie {
		return vl.redirectToLogin(w, r)
	} else if err != nil {
		return caddyauth.User{}, false, err
	}

	// If we see a malformed cookie, we assume it's due to some tinkering or old
	// version of this plugin. In that case, we'll redirect the user to the login
	// page to reauthenticate.
	cookieParts := strings.Split(cookie.Value, ".")
	if len(cookieParts) != 2 {
		return vl.redirectToLogin(w, r)
	}
	phoneNumberBytes, err := base64.StdEncoding.DecodeString(cookieParts[0])
	if err != nil {
		return vl.redirectToLogin(w, r)
	}
	phoneNumber := string(phoneNumberBytes)
	fmt.Println("phoneNumber", phoneNumber)
	actualMAC, err := base64.StdEncoding.DecodeString(cookieParts[1])
	if err != nil {
		return vl.redirectToLogin(w, r)
	}
	mac := hmac.New(sha256.New, vl.signingKey)
	mac.Write(phoneNumberBytes)
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(actualMAC, expectedMAC) {
		return vl.redirectToLogin(w, r)
	}

	for _, n := range numbers {
		if phoneNumber == n {
			return caddyauth.User{ID: phoneNumber}, true, nil
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("Access denied"))
	return caddyauth.User{}, false, nil
}

func (vl VippsLogin) redirectToLogin(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	conf := vl.oauth2conf()
	url := conf.AuthCodeURL(base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("URL: %s", r.URL.String()))), oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusSeeOther)
	return caddyauth.User{}, false, nil
}

func (vl VippsLogin) oauth2conf() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     vl.ClientID,
		ClientSecret: vl.ClientSecret,
		Scopes:       []string{"phoneNumber"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://api.vipps.no/access-management-1.0/access/oauth2/auth",
			TokenURL:  "https://api.vipps.no/access-management-1.0/access/oauth2/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: vl.RedirectURL,
	}
}
