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

// Package apk implements Android APK scanning and analysis for MORF.
package apk

// This file contains the exported-component and deep-link exposure analyzer
// (unit P2a / #7d). It consumes the already-parsed manifest component models
// produced by manifest_parser.go and turns them into []models.PlatformFinding
// without re-parsing the manifest.
//
// MASVS mapping:
//   - MASVS-PLATFORM-1: "The app only exposes sensitive functionality to other
//     apps through app components whose access is properly restricted." Covers
//     exported components without permission guards AND deep-link hijack
//     surfaces (browsable custom schemes, app-links missing autoVerify).
//   - MASVS-PLATFORM-3 would cover URL-scheme confirmation flows; we use
//     PLATFORM-1 here because the IPC surface exposure is the root cause.

import (
	"fmt"
	"strings"

	"morf/models"
)

const (
	// masvsIDPlatform1 is the OWASP MASVS control for IPC surface exposure.
	// MASVS-PLATFORM-1: "The app only exposes sensitive functionality to other
	// apps through app components whose access is properly restricted."
	masvsIDPlatform1 = "MASVS-PLATFORM-1"

	// ruleExportedNoPermission is the stable rule ID for an exported component
	// that has no android:permission (or read/write-permission for providers)
	// protecting access to it.
	ruleExportedNoPermission = "exported-component-no-permission"

	// ruleBrowsableCustomScheme is the stable rule ID for a browsable intent
	// filter that declares a non-http/https scheme (potential scheme hijack).
	ruleBrowsableCustomScheme = "browsable-custom-scheme-deeplink"

	// ruleAppLinkNoAutoVerify is the stable rule ID for an https app-link
	// intent filter that is missing android:autoVerify="true".
	ruleAppLinkNoAutoVerify = "app-link-no-autoverify"

	// categoryPlatform is the finding category for manifest exposure findings.
	categoryPlatform = "platform"

	// locationManifest is the file location reported for all manifest findings.
	locationManifest = "AndroidManifest.xml"

	// browsableCategory is the Android intent category value that marks an
	// intent filter as reachable from the browser / deep-link dispatcher.
	browsableCategory = "android.intent.category.BROWSABLE"
)

// AnalyzeExposure consumes the already-parsed Android manifest component sets
// from a models.MetaDataModel and returns a []models.PlatformFinding covering:
//
//   - Exported activities, services, broadcast receivers, and content providers
//     that have no enforcing android:permission (or, for providers, no
//     read/write-permission either). ContentProvider findings are promoted to
//     SeverityHigh; all others are SeverityMedium.
//     Rule: "exported-component-no-permission", MASVS-PLATFORM-1.
//
//   - Browsable intent filters on any component that declare a non-http/https
//     scheme (custom-scheme deep-links susceptible to intent/scheme hijacking).
//     Rule: "browsable-custom-scheme-deeplink", MASVS-PLATFORM-1, SeverityMedium.
//
//   - Https app-link intent filters (scheme=https + category BROWSABLE) that
//     do NOT set android:autoVerify="true". Without autoVerify Android does not
//     verify domain ownership, so any app can register the same intent filter
//     and intercept the link.
//     Rule: "app-link-no-autoverify", MASVS-PLATFORM-1, SeverityLow.
//
// The function is pure: it performs no I/O and does not modify the metadata.
// It is safe to call from tests without any aapt/apktool toolchain present.
func AnalyzeExposure(meta *models.MetaDataModel) []models.PlatformFinding {
	if meta == nil {
		return nil
	}

	var findings []models.PlatformFinding

	// --- Activities ---
	for _, a := range meta.AndroidManifest.Activities {
		if !a.Exported {
			continue
		}
		if a.Permission == "" {
			findings = append(findings, newExportedFinding(a.Name, "activity", models.SeverityMedium))
		}
		findings = append(findings, analyzeIntentFilters(a.Name, a.IntentFilters)...)
	}

	// --- Services ---
	for _, s := range meta.AndroidManifest.Services {
		if !s.Exported {
			continue
		}
		if s.Permission == "" {
			findings = append(findings, newExportedFinding(s.Name, "service", models.SeverityMedium))
		}
		findings = append(findings, analyzeIntentFilters(s.Name, s.IntentFilters)...)
	}

	// --- Broadcast Receivers ---
	for _, r := range meta.AndroidManifest.BroadcastReceivers {
		if !r.Exported {
			continue
		}
		if r.Permission == "" {
			findings = append(findings, newExportedFinding(r.Name, "receiver", models.SeverityMedium))
		}
		findings = append(findings, analyzeIntentFilters(r.Name, r.IntentFilters)...)
	}

	// --- Content Providers (high severity; also need read/writePermission) ---
	for _, p := range meta.AndroidManifest.ContentProviders {
		if !p.Exported {
			continue
		}
		// A ContentProvider is considered permission-guarded when it has at
		// least one of: android:permission, or BOTH android:readPermission and
		// android:writePermission. An asymmetrically guarded provider (e.g.
		// only readPermission) is still flagged because write access is open.
		if !providerIsPermissionGuarded(p) {
			findings = append(findings, newExportedFinding(p.Name, "provider", models.SeverityHigh))
		}
	}

	return findings
}

// providerIsPermissionGuarded returns true when the provider has a permission
// attribute that restricts both read and write access. Accepted cases:
//   - android:permission is set (covers all access), OR
//   - android:readPermission AND android:writePermission are both set.
//
// A single-sided permission (only read or only write) is NOT considered fully
// guarded because the unprotected direction remains open.
func providerIsPermissionGuarded(p models.ManifestProviderInfo) bool {
	if p.Permission != "" {
		return true
	}
	return p.ReadPermission != "" && p.WritePermission != ""
}

// newExportedFinding builds a PlatformFinding for an exported component
// without a permission guard.
func newExportedFinding(componentName, componentType string, severity models.PlatformFindingSeverity) models.PlatformFinding {
	f := models.PlatformFinding{
		RuleID:   ruleExportedNoPermission,
		Title:    "Exported component without permission guard",
		Severity: severity,
		MASVSID:  masvsIDPlatform1,
		Category: categoryPlatform,
		Location: locationManifest,
		Evidence: fmt.Sprintf("%s (%s): exported=true, no android:permission", componentName, componentType),
		Tier:     models.TierForSeverity(severity),
	}
	return f
}

// analyzeIntentFilters inspects each intent filter on a component and emits
// findings for custom-scheme browsable deep-links and missing autoVerify.
func analyzeIntentFilters(componentName string, filters []models.ManifestFilter) []models.PlatformFinding {
	var findings []models.PlatformFinding

	for _, filter := range filters {
		isBrowsable := hasBrowsableCategory(filter)
		for _, data := range filter.Data {
			if data.Scheme == "" {
				continue
			}
			scheme := strings.ToLower(data.Scheme)

			switch {
			case scheme != "http" && scheme != "https":
				// Custom scheme with BROWSABLE category -> potential scheme hijack.
				if isBrowsable {
					findings = append(findings, customSchemeFinding(data.Scheme, data.Host))
				}

			case scheme == "https" && isBrowsable:
				// https App Link: flag when autoVerify is missing.
				if !filter.AutoVerify {
					findings = append(findings, appLinkNoAutoVerifyFinding(componentName, data.Host))
				}
				// https WITH autoVerify=true is the correct pattern — no finding.
			}
		}
	}

	return findings
}

// hasBrowsableCategory reports whether the intent filter declares the
// android.intent.category.BROWSABLE category.
func hasBrowsableCategory(filter models.ManifestFilter) bool {
	for _, cat := range filter.Categories {
		if cat == browsableCategory {
			return true
		}
	}
	return false
}

// customSchemeFinding builds a PlatformFinding for a browsable intent filter
// that uses a non-http/https URI scheme.
func customSchemeFinding(scheme, host string) models.PlatformFinding {
	evidence := scheme + "://"
	if host != "" {
		evidence += host
	}
	return models.PlatformFinding{
		RuleID:   ruleBrowsableCustomScheme,
		Title:    "Browsable custom-scheme deep-link (potential scheme hijack)",
		Severity: models.SeverityMedium,
		MASVSID:  masvsIDPlatform1,
		Category: categoryPlatform,
		Location: locationManifest,
		Evidence: evidence,
		Tier:     models.TierForSeverity(models.SeverityMedium),
	}
}

// appLinkNoAutoVerifyFinding builds a PlatformFinding for an https app-link
// intent filter that is missing android:autoVerify="true".
func appLinkNoAutoVerifyFinding(componentName, host string) models.PlatformFinding {
	evidence := host
	if evidence == "" {
		evidence = componentName
	}
	return models.PlatformFinding{
		RuleID:   ruleAppLinkNoAutoVerify,
		Title:    "App Link intent-filter missing android:autoVerify",
		Severity: models.SeverityLow,
		MASVSID:  masvsIDPlatform1,
		Category: categoryPlatform,
		Location: locationManifest,
		Evidence: evidence,
		Tier:     models.TierForSeverity(models.SeverityLow),
	}
}
