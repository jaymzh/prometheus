// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/cloudflare/cloudflared/token"
	"github.com/rs/zerolog"
)

// cfAccessAuthType is the value of authorization.type in an HTTP client
// config file (--http.config.file) that selects Cloudflare Access
// authentication instead of a real HTTP Authorization scheme.
const cfAccessAuthType = "cf-access"

// cfAccessTokenHeader is the header Cloudflare Access checks for a JWT
// obtained through its browser-based login flow.
//
// See https://developers.cloudflare.com/cloudflare-one/tutorials/cli/#curl.
const cfAccessTokenHeader = "Cf-Access-Token"

// cfAccessRoundTripper attaches a Cloudflare Access token to every request
// before forwarding it to the wrapped RoundTripper.
type cfAccessRoundTripper struct {
	token string
	next  http.RoundTripper
}

// newCFAccessRoundTripper logs in to the Cloudflare Access application
// protecting appURL, reusing a cached token when one is already valid, and
// returns a RoundTripper that attaches the resulting token to every request
// forwarded to next. It may open a browser window and block until the login
// flow completes.
func newCFAccessRoundTripper(appURL *url.URL, next http.RoundTripper) (http.RoundTripper, error) {
	token.Init("promtool")

	appInfo, err := token.GetAppInfo(appURL)
	if err != nil {
		return nil, fmt.Errorf("failed to detect Cloudflare Access application for %s: %w", appURL, err)
	}

	cfLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"}).With().Timestamp().Logger()
	tok, err := token.FetchToken(appURL, appInfo, false, false, &cfLogger)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Cloudflare Access token: %w", err)
	}

	return &cfAccessRoundTripper{token: tok, next: next}, nil
}

// RoundTrip implements http.RoundTripper.
func (rt *cfAccessRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(cfAccessTokenHeader, rt.token)
	return rt.next.RoundTrip(req)
}
