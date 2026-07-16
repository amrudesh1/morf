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

// Package verify performs OPTIONAL live verification of detected secrets: it
// attempts to determine whether a candidate credential is currently valid by
// making a minimal, read-only call to the credential's provider. Verification
// is OFF by default and only runs when the operator explicitly opts in via the
// MORF_ENABLE_VERIFICATION=true environment variable, since it makes outbound
// network requests with (potentially real) third-party credentials.
package verify

import (
	"context"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"morf/models"
)

// envVerificationEnabled is the environment variable that gates all live,
// outbound verification. Verification runs ONLY when it is exactly "true".
const envVerificationEnabled = "MORF_ENABLE_VERIFICATION"

// VerifySecrets sets each finding's VerificationStatus. It runs in the scan
// pipeline immediately after detect.ApplyPrecision.
//
// Intended behavior (to be implemented by the verification feature agent):
//
//   - Dispatch each finding to a per-provider verifier selected by the owning
//     secret type (e.g. AWS STS GetCallerIdentity for AWS keys, a token
//     introspection / whoami endpoint for GitHub/Slack/GCP/Stripe tokens). Each
//     verifier makes a single, minimal, READ-ONLY request and never mutates the
//     provider account.
//   - Honor the supplied ctx for per-request timeouts and cancellation, bound
//     concurrency, and rate-limit outbound calls so a large finding set cannot
//     hammer a provider.
//   - Map the outcome to VerificationStatus:
//   - "active"    — the provider confirmed the credential is valid/live.
//   - "inactive"  — the provider confirmed the credential is revoked/invalid.
//   - "unknown"   — no verifier exists for the type, or the check was
//     inconclusive (network error, ambiguous response, rate-limited).
//   - "unchecked" — verification was disabled (the default; see below).
//
// DEFAULT-OFF: when MORF_ENABLE_VERIFICATION is not exactly "true", this makes
// NO network calls, sets every finding's VerificationStatus to "unchecked", and
// returns the slice otherwise unchanged.
func VerifySecrets(ctx context.Context, secrets []models.SecretModel) []models.SecretModel {
	if os.Getenv(envVerificationEnabled) != "true" {
		for i := range secrets {
			secrets[i].VerificationStatus = statusUnchecked
		}
		return secrets
	}
	return verifyWithRegistry(ctx, secrets, defaultRegistry(sharedClient))
}

// VerifySecretsForced runs the verification path UNCONDITIONALLY (ignoring the
// MORF_ENABLE_VERIFICATION env gate). It exists so an explicit, per-call opt-in
// (e.g. an MCP tool argument or a CLI --verify flag) can enable verification for
// that call ONLY, without mutating the process-global env var — which would
// otherwise stick ON for every subsequent call and race under concurrency. All
// the same safety controls apply (shared client, no-redirect, rate limit, cache,
// read-only providers). Callers that want the default-off behavior should use
// VerifySecrets instead.
func VerifySecretsForced(ctx context.Context, secrets []models.SecretModel) []models.SecretModel {
	return verifyWithRegistry(ctx, secrets, defaultRegistry(sharedClient))
}

// sharedClient is the process-wide verification client (single HTTP client,
// global rate limiter, shared cache). It is created once so its safety controls
// apply across every VerifySecrets call in the process.
var sharedClient = newClient()

// verifyWithRegistry runs the enabled verification path against the supplied
// registry. It is the seam the tests drive so they never touch the real
// providers or the package-level sharedClient/registry.
//
// For each finding: an empty candidate string, or a SecretType with no
// registered verifier, is left as "unknown" (never "active"/"inactive" without
// an actual check). Otherwise the per-type verifier runs behind the shared
// cache and global rate limiter; a transport error or ambiguous response yields
// "unknown". The raw secret value is NEVER logged.
func verifyWithRegistry(ctx context.Context, secrets []models.SecretModel, registry []registryEntry) []models.SecretModel {
	// A single reusable client backs the registry entries; recover its cache.
	var c *client
	if len(registry) > 0 {
		if v, ok := registry[0].verifier.(interface{ shared() *client }); ok {
			c = v.shared()
		}
	}

	// AWS findings need slice-aware pairing (an AKIA access key ID plus a
	// candidate 40-char secret access key from the same scan), which the
	// single-string Verifier interface cannot express. Handle them in a pre-pass
	// and record which indices are already resolved so the main loop skips them.
	handled := awsPrePass(ctx, secrets, registry, c)

	for i := range secrets {
		if handled[i] {
			continue
		}
		candidate := secrets[i].SecretString
		v := lookup(registry, secrets[i].SecretType)
		if v == nil || candidate == "" {
			secrets[i].VerificationStatus = statusUnknown
			continue
		}

		key := hashSecret(candidate)
		if c != nil {
			if cached, ok := c.cacheGet(key); ok {
				secrets[i].VerificationStatus = cached
				continue
			}
		}

		status, err := v.Verify(ctx, candidate)
		if err != nil {
			// Do NOT include the secret; log only the type for observability.
			log.WithField("secretType", secrets[i].SecretType).
				Debug("verify: verification request failed; marking unknown")
			status = statusUnknown
		}
		if status != statusActive && status != statusInactive && status != statusUnknown {
			status = statusUnknown
		}
		if c != nil {
			c.cacheSet(key, status)
		}
		secrets[i].VerificationStatus = status
	}
	return secrets
}

// awsPrePass resolves AWS access-key-ID findings by pairing each with the best
// co-located candidate 40-char secret access key from the same batch and
// running a SigV4-signed STS GetCallerIdentity check. It stamps the AKIA
// finding's VerificationStatus in place and returns a set (by index) of the
// findings it handled so the main loop does not re-process them.
//
// An AKIA id with no candidate secret in the batch stays "unknown" (never a
// false "active"). Results are cached by hash(accessKeyID+":"+secretKey) so the
// same pair is not re-checked within the TTL.
func awsPrePass(ctx context.Context, secrets []models.SecretModel, registry []registryEntry, c *client) map[int]bool {
	handled := make(map[int]bool)

	// Only run if an AWS verifier is registered.
	var av *awsVerifier
	for _, e := range registry {
		if a, ok := e.verifier.(*awsVerifier); ok {
			av = a
			break
		}
	}
	if av == nil {
		return handled
	}

	for i := range secrets {
		st := strings.ToLower(secrets[i].SecretType)
		val := strings.TrimSpace(secrets[i].SecretString)
		if !strings.Contains(st, "aws") || !awsPairablePattern.MatchString(val) {
			// Only long-term AKIA keys are pairable/verifiable here; ASIA
			// (temporary) and other prefixes fall through to the single-string
			// awsVerifier, which returns "unknown" (never a false "inactive").
			continue
		}
		handled[i] = true // a pairable AWS access key ID: this pre-pass owns its status.

		candidates := collectAWSSecretCandidates(secrets, i)
		if len(candidates) == 0 {
			// No paired secret available: nothing safe to verify.
			secrets[i].VerificationStatus = statusUnknown
			continue
		}

		// Track outcomes across candidates. "active" is definitive and wins
		// immediately. If every candidate was definitively rejected (inactive)
		// with no inconclusive result, the id+secret pairing is invalid overall.
		// Any inconclusive (unknown / transport error) keeps the result unknown
		// so we never overclaim.
		status := statusUnknown
		sawInactive := false
		sawUnknown := false
		for _, secretKey := range candidates {
			key := hashSecret(val + ":" + secretKey)
			var s string
			if c != nil {
				if cached, ok := c.cacheGet(key); ok {
					s = cached
				}
			}
			if s == "" {
				var err error
				s, err = av.verifyPair(ctx, val, secretKey)
				if err != nil {
					log.WithField("secretType", secrets[i].SecretType).
						Debug("verify: AWS pair verification failed; trying next candidate")
					sawUnknown = true
					continue
				}
				if c != nil {
					c.cacheSet(key, s)
				}
			}
			switch s {
			case statusActive:
				status = statusActive
			case statusInactive:
				sawInactive = true
			default:
				sawUnknown = true
			}
			if status == statusActive {
				break
			}
		}
		if status != statusActive {
			if sawInactive && !sawUnknown {
				status = statusInactive
			} else {
				status = statusUnknown
			}
		}
		secrets[i].VerificationStatus = status
	}
	return handled
}
