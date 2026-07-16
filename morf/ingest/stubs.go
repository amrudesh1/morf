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

package ingest

import (
	"context"
	"fmt"
)

// Vendor scheme names for the documented stub adapters. These are registered so
// `morf fetch appstoreconnect://<build>` returns a precise, actionable "configure
// X" error rather than an "unknown scheme" error — the interface, registration
// and error surface exist now; only the vendor auth body is TODO. The auth
// mechanism and required env vars for each are documented in docs/INGESTION.md.
const (
	schemeAppStoreConnect = "appstoreconnect"
	schemeTestFlight      = "testflight"
	schemeXcodeCloud      = "xcodecloud"
	schemeGooglePlay      = "googleplay"
)

// stubAdapter is a documented, not-yet-implemented vendor adapter. Its Fetch
// always returns an error wrapping ErrAdapterNotConfigured that names the exact
// env vars/config the future implementation will require, so the failure is
// actionable and machine-detectable (errors.Is).
type stubAdapter struct {
	scheme  string
	envVars string // human-readable list of required config, for the error
	auth    string // one-line description of the vendor auth mechanism
}

func init() {
	Register(schemeAppStoreConnect, stubFactory(schemeAppStoreConnect,
		"MORF_ASC_ISSUER_ID, MORF_ASC_KEY_ID, MORF_ASC_PRIVATE_KEY",
		"App Store Connect API ES256 JWT signed with a .p8 private key"))
	Register(schemeTestFlight, stubFactory(schemeTestFlight,
		"MORF_ASC_ISSUER_ID, MORF_ASC_KEY_ID, MORF_ASC_PRIVATE_KEY",
		"App Store Connect API JWT (shared with App Store Connect); resolves a TestFlight build"))
	Register(schemeXcodeCloud, stubFactory(schemeXcodeCloud,
		"MORF_ASC_ISSUER_ID, MORF_ASC_KEY_ID, MORF_ASC_PRIVATE_KEY, MORF_XCODE_CLOUD_PRODUCT_ID",
		"App Store Connect API JWT plus an Xcode Cloud CI product/build id"))
	Register(schemeGooglePlay, stubFactory(schemeGooglePlay,
		"MORF_GOOGLE_PLAY_SA_JSON",
		"Google Play Developer API OAuth2 with a service-account JSON key"))
}

func stubFactory(scheme, envVars, auth string) Factory {
	return func(Options) (Adapter, error) {
		return &stubAdapter{scheme: scheme, envVars: envVars, auth: auth}, nil
	}
}

func (a *stubAdapter) Scheme() string { return a.scheme }

func (a *stubAdapter) Fetch(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("%w: %s ingestion is not implemented — it requires %s (%s); see docs/INGESTION.md",
		ErrAdapterNotConfigured, a.scheme, a.envVars, a.auth)
}
