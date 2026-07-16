/*
Copyright [2023] [Amrudesh Balakrishnan]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package verify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// Provider endpoint bases. These are package variables (not constants) ONLY so
// tests can point them at net/http/httptest mock servers; production code never
// mutates them. Every endpoint below is a READ-ONLY (GET) introspection /
// whoami / balance-read endpoint — none create, modify, or delete provider
// state.
var (
	githubAPIBase       = "https://api.github.com"
	slackAPIBase        = "https://slack.com"
	stripeAPIBase       = "https://api.stripe.com"
	googleAPIBase       = "https://www.googleapis.com"
	twilioAPIBase       = "https://api.twilio.com"
	gitlabAPIBase       = "https://gitlab.com"
	sendgridAPIBase     = "https://api.sendgrid.com"
	npmAPIBase          = "https://registry.npmjs.org"
	cloudflareAPIBase   = "https://api.cloudflare.com"
	mailgunAPIBase      = "https://api.mailgun.net"
	digitalOceanAPIBase = "https://api.digitalocean.com"
)

// githubVerifier validates a GitHub token via GET /user (the authenticated-user
// whoami endpoint). 200 => active, 401 => inactive, anything else => unknown.
type githubVerifier struct{ c *client }

func (v *githubVerifier) Verify(ctx context.Context, secret string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPIBase+"/user", nil)
	if err != nil {
		return statusUnknown, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return statusActive, nil
	case http.StatusUnauthorized:
		return statusInactive, nil
	default:
		return statusUnknown, nil
	}
}

// slackVerifier validates a Slack token via GET auth.test. Slack returns HTTP
// 200 even for a bad token, encoding validity in the JSON body's "ok" field.
type slackVerifier struct{ c *client }

func (v *slackVerifier) Verify(ctx context.Context, secret string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, slackAPIBase+"/api/auth.test", nil)
	if err != nil {
		return statusUnknown, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		return statusUnknown, nil
	}
	var body struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return statusUnknown, nil
	}
	if body.OK {
		return statusActive, nil
	}
	// A well-formed negative response ("invalid_auth"/"not_authed"/etc.) is a
	// definitive inactive; an unexpected empty error is inconclusive.
	if body.Error != "" {
		return statusInactive, nil
	}
	return statusUnknown, nil
}

// stripeVerifier validates a Stripe secret key via GET /v1/balance, using the
// key as the HTTP basic-auth username (Stripe's documented auth scheme).
// 200 => active, 401 => inactive.
type stripeVerifier struct{ c *client }

func (v *stripeVerifier) Verify(ctx context.Context, secret string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stripeAPIBase+"/v1/balance", nil)
	if err != nil {
		return statusUnknown, err
	}
	// Key as basic-auth username, empty password (Stripe convention).
	req.SetBasicAuth(secret, "")
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return statusActive, nil
	case http.StatusUnauthorized:
		return statusInactive, nil
	default:
		return statusUnknown, nil
	}
}

// twilioVerifier validates a Twilio credential by reading the Accounts list
// endpoint (a GET). The key is used as the basic-auth username. Twilio returns
// 401 for a bad credential. 200 => active, 401 => inactive.
type twilioVerifier struct{ c *client }

func (v *twilioVerifier) Verify(ctx context.Context, secret string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, twilioAPIBase+"/2010-04-01/Accounts.json", nil)
	if err != nil {
		return statusUnknown, err
	}
	req.SetBasicAuth(secret, "")
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return statusActive, nil
	case http.StatusUnauthorized:
		return statusInactive, nil
	default:
		return statusUnknown, nil
	}
}

// googleVerifier validates a Google API key with a benign, read-only probe: the
// Books API volumes search, which accepts an API key via ?key= and is a pure
// read. Google's key-validity signalling is nuanced, so the mapping is
// deliberately conservative:
//
//   - 200                     => active (key accepted).
//   - 400 with reason keyInvalid / API_KEY_INVALID => inactive (key rejected).
//   - 401/403 (permission / API-not-enabled / restricted) => unknown: the key
//     may well be valid but scoped away from this API, so we must not claim it
//     is inactive.
//   - anything else / ambiguous => unknown.
type googleVerifier struct{ c *client }

func (v *googleVerifier) Verify(ctx context.Context, secret string) (string, error) {
	u := googleAPIBase + "/books/v1/volumes?country=US&q=morf&maxResults=1&key=" + url.QueryEscape(secret)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return statusUnknown, err
	}
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	if resp.StatusCode == http.StatusOK {
		return statusActive, nil
	}
	if resp.StatusCode == http.StatusBadRequest {
		var body struct {
			Error struct {
				Status  string `json:"status"`
				Message string `json:"message"`
				Errors  []struct {
					Reason string `json:"reason"`
				} `json:"errors"`
			} `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
			reason := strings.ToLower(body.Error.Status + " " + body.Error.Message)
			for _, e := range body.Error.Errors {
				reason += " " + strings.ToLower(e.Reason)
			}
			if strings.Contains(reason, "keyinvalid") ||
				strings.Contains(reason, "api_key_invalid") ||
				strings.Contains(reason, "api key not valid") {
				return statusInactive, nil
			}
		}
		// A 400 we cannot attribute to an invalid key is inconclusive.
		return statusUnknown, nil
	}
	// 401/403 and everything else: cannot distinguish a scoped-but-valid key
	// from a dead one, so stay conservative.
	return statusUnknown, nil
}

// gitlabVerifier validates a GitLab token via GET /api/v4/user (the current-user
// whoami endpoint). 200 => active, 401 => inactive, anything else => unknown.
type gitlabVerifier struct{ c *client }

func (v *gitlabVerifier) Verify(ctx context.Context, secret string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gitlabAPIBase+"/api/v4/user", nil)
	if err != nil {
		return statusUnknown, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return statusActive, nil
	case http.StatusUnauthorized:
		return statusInactive, nil
	default:
		return statusUnknown, nil
	}
}

// sendgridVerifier validates a SendGrid API key via GET /v3/scopes (a read of
// the key's own granted scopes). 200 => active, 401 => inactive.
type sendgridVerifier struct{ c *client }

func (v *sendgridVerifier) Verify(ctx context.Context, secret string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sendgridAPIBase+"/v3/scopes", nil)
	if err != nil {
		return statusUnknown, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return statusActive, nil
	case http.StatusUnauthorized:
		return statusInactive, nil
	default:
		return statusUnknown, nil
	}
}

// npmVerifier validates an npm access token via GET /-/whoami. 200 => active,
// 401 => inactive.
type npmVerifier struct{ c *client }

func (v *npmVerifier) Verify(ctx context.Context, secret string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, npmAPIBase+"/-/whoami", nil)
	if err != nil {
		return statusUnknown, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return statusActive, nil
	case http.StatusUnauthorized:
		return statusInactive, nil
	default:
		return statusUnknown, nil
	}
}

// cloudflareVerifier validates a Cloudflare API token via GET
// /client/v4/user/tokens/verify. Cloudflare returns HTTP 200 with a JSON body
// whose success flag and result.status ("active") signal validity; a bad token
// yields 401. Mirrors the Slack JSON-body pattern.
type cloudflareVerifier struct{ c *client }

func (v *cloudflareVerifier) Verify(ctx context.Context, secret string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudflareAPIBase+"/client/v4/user/tokens/verify", nil)
	if err != nil {
		return statusUnknown, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	if resp.StatusCode == http.StatusUnauthorized {
		return statusInactive, nil
	}
	if resp.StatusCode != http.StatusOK {
		return statusUnknown, nil
	}
	var body struct {
		Success bool `json:"success"`
		Result  struct {
			Status string `json:"status"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return statusUnknown, nil
	}
	if body.Success && strings.EqualFold(body.Result.Status, "active") {
		return statusActive, nil
	}
	// A well-formed 200 that is not success+active is a definitive negative.
	return statusInactive, nil
}

// mailgunVerifier validates a Mailgun API key via GET /v3/domains, using the
// key as the HTTP basic-auth password with username "api" (Mailgun's documented
// auth scheme). 200 => active, 401 => inactive.
type mailgunVerifier struct{ c *client }

func (v *mailgunVerifier) Verify(ctx context.Context, secret string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mailgunAPIBase+"/v3/domains", nil)
	if err != nil {
		return statusUnknown, err
	}
	req.SetBasicAuth("api", secret)
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return statusActive, nil
	case http.StatusUnauthorized:
		return statusInactive, nil
	default:
		return statusUnknown, nil
	}
}

// digitalOceanVerifier validates a DigitalOcean token via GET /v2/account.
// 200 => active, 401 => inactive.
type digitalOceanVerifier struct{ c *client }

func (v *digitalOceanVerifier) Verify(ctx context.Context, secret string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, digitalOceanAPIBase+"/v2/account", nil)
	if err != nil {
		return statusUnknown, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := v.c.do(ctx, req)
	if err != nil {
		return statusUnknown, err
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return statusActive, nil
	case http.StatusUnauthorized:
		return statusInactive, nil
	default:
		return statusUnknown, nil
	}
}

// shared exposes the underlying shared client so the orchestrator can reach the
// common cache/limiter without knowing the concrete verifier type. Every
// verifier in a given registry is constructed with the same *client.
func (v *githubVerifier) shared() *client       { return v.c }
func (v *slackVerifier) shared() *client        { return v.c }
func (v *stripeVerifier) shared() *client       { return v.c }
func (v *twilioVerifier) shared() *client       { return v.c }
func (v *googleVerifier) shared() *client       { return v.c }
func (v *gitlabVerifier) shared() *client       { return v.c }
func (v *sendgridVerifier) shared() *client     { return v.c }
func (v *npmVerifier) shared() *client          { return v.c }
func (v *cloudflareVerifier) shared() *client   { return v.c }
func (v *mailgunVerifier) shared() *client      { return v.c }
func (v *digitalOceanVerifier) shared() *client { return v.c }

// drain closes a response body after reading a bounded amount so the underlying
// connection can be reused, without slurping unbounded provider output.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_ = resp.Body.Close()
}
