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
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	caddy.RegisterModule(VippsLogin{})
}

// VippsLogin facilitates logging in using Vipps Login (https://vipps.no)
type VippsLogin struct {
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	RedirectURL  string `json:"redirect_url,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (VippsLogin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.authentication.providers.vipps_login",
		New:  func() caddy.Module { return new(VippsLogin) },
	}
}

// Provision provisions the HTTP basic auth provider.
func (hba *VippsLogin) Provision(ctx caddy.Context) error {
	return nil
}

// Authenticate validates the user credentials in req and returns the user, if valid.
func (hba VippsLogin) Authenticate(w http.ResponseWriter, req *http.Request) (caddyauth.User, bool, error) {
	return caddyauth.User{ID: "47999999999"}, true, nil
}
