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
	"strings"
)

// Verification status constants. These mirror the values documented on
// models.SecretModel.VerificationStatus.
const (
	statusActive    = "active"
	statusInactive  = "inactive"
	statusUnknown   = "unknown"
	statusUnchecked = "unchecked"
)

// Verifier performs a single, minimal, READ-ONLY request to a credential's
// provider to determine whether the credential is currently valid.
//
// Implementations MUST NOT perform any mutating (create/update/delete) request,
// MUST honor ctx for cancellation/timeout, and MUST NOT log the raw secret.
//
// The returned status is one of statusActive, statusInactive, or statusUnknown.
// An error is returned only for transport-level / inconclusive failures; callers
// treat a non-nil error as statusUnknown.
type Verifier interface {
	Verify(ctx context.Context, secret string) (status string, err error)
}

// registryEntry pairs a lower-cased SecretType substring with the verifier that
// handles any finding whose SecretType contains that substring. Order matters:
// the first matching entry wins, so more specific substrings are listed first.
type registryEntry struct {
	match    string
	verifier Verifier
}

// defaultRegistry is the ordered set of provider verifiers. It is built lazily
// so the shared HTTP client / rate limiter are constructed once per process.
//
// Matching is case-insensitive and substring-based against SecretModel.SecretType
// (which is populated from the owning pattern's name, e.g. "GitHub",
// "Slack Token", "Stripe API Key", "Google API Key", "Twilio API Key",
// "AWS API Key").
func defaultRegistry(c *client) []registryEntry {
	return []registryEntry{
		{match: "github", verifier: &githubVerifier{c: c}},
		{match: "gitlab", verifier: &gitlabVerifier{c: c}},
		{match: "slack", verifier: &slackVerifier{c: c}},
		{match: "stripe", verifier: &stripeVerifier{c: c}},
		{match: "google", verifier: &googleVerifier{c: c}},
		{match: "gcp", verifier: &googleVerifier{c: c}},
		{match: "twilio", verifier: &twilioVerifier{c: c}},
		{match: "sendgrid", verifier: &sendgridVerifier{c: c}},
		{match: "npm", verifier: &npmVerifier{c: c}},
		{match: "cloudflare", verifier: &cloudflareVerifier{c: c}},
		{match: "mailgun", verifier: &mailgunVerifier{c: c}},
		{match: "digitalocean", verifier: &digitalOceanVerifier{c: c}},
		{match: "aws", verifier: &awsVerifier{c: c}},
	}
}

// lookup returns the first verifier whose match substring is contained in the
// (case-insensitively normalized) secretType, or nil if none applies.
func lookup(registry []registryEntry, secretType string) Verifier {
	st := strings.ToLower(strings.TrimSpace(secretType))
	if st == "" {
		return nil
	}
	for _, e := range registry {
		if strings.Contains(st, e.match) {
			return e.verifier
		}
	}
	return nil
}
