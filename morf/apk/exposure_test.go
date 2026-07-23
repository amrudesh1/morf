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

package apk

// Unit tests for the manifest exposure analyzer in exposure.go.
// Every test uses hand-crafted models.MetaDataModel instances so there is no
// dependency on aapt, apktool, or any real APK file.

import (
	"testing"

	"morf/models"
)

// makeMetaWithComponents is a helper that returns a *models.MetaDataModel
// pre-populated with the given component slices.
func makeMetaWithComponents(
	activities []models.ManifestActivityInfo,
	services []models.ManifestServiceInfo,
	receivers []models.ManifestReceiverInfo,
	providers []models.ManifestProviderInfo,
) *models.MetaDataModel {
	meta := &models.MetaDataModel{}
	meta.AndroidManifest.Activities = models.JSONComponentArray[models.ManifestActivityInfo](activities)
	meta.AndroidManifest.Services = models.JSONComponentArray[models.ManifestServiceInfo](services)
	meta.AndroidManifest.BroadcastReceivers = models.JSONComponentArray[models.ManifestReceiverInfo](receivers)
	meta.AndroidManifest.ContentProviders = models.JSONComponentArray[models.ManifestProviderInfo](providers)
	return meta
}

// findFindingByRule returns the first PlatformFinding with the given ruleId,
// or nil when none is present.
func findFindingByRule(findings []models.PlatformFinding, ruleID string) *models.PlatformFinding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// countByRule returns the number of findings with the given ruleId.
func countByRule(findings []models.PlatformFinding, ruleID string) int {
	n := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			n++
		}
	}
	return n
}

// -------------------------------------------------------------------------
// (a) Exported activity without permission → exported-component-no-permission
// -------------------------------------------------------------------------

func TestAnalyzeExposure_ExportedActivityNoPermission(t *testing.T) {
	meta := makeMetaWithComponents(
		[]models.ManifestActivityInfo{
			{Name: "com.example.OpenActivity", Exported: true, Permission: ""},
		},
		nil, nil, nil,
	)

	findings := AnalyzeExposure(meta)

	f := findFindingByRule(findings, ruleExportedNoPermission)
	if f == nil {
		t.Fatalf("expected finding %q for exported activity, got none; all findings: %v", ruleExportedNoPermission, findings)
	}
	if f.MASVSID != "MASVS-PLATFORM-1" {
		t.Errorf("MASVSID = %q, want MASVS-PLATFORM-1", f.MASVSID)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q, want medium (activity)", f.Severity)
	}
	if f.Category != categoryPlatform {
		t.Errorf("Category = %q, want %q", f.Category, categoryPlatform)
	}
	if f.Location != locationManifest {
		t.Errorf("Location = %q, want %q", f.Location, locationManifest)
	}
}

// -------------------------------------------------------------------------
// (b) Exported ContentProvider without any permission → high severity
// -------------------------------------------------------------------------

func TestAnalyzeExposure_ExportedProviderNoPermission(t *testing.T) {
	meta := makeMetaWithComponents(
		nil, nil, nil,
		[]models.ManifestProviderInfo{
			{
				Name:            "com.example.DataProvider",
				Exported:        true,
				Permission:      "",
				ReadPermission:  "",
				WritePermission: "",
			},
		},
	)

	findings := AnalyzeExposure(meta)

	f := findFindingByRule(findings, ruleExportedNoPermission)
	if f == nil {
		t.Fatalf("expected finding %q for exported provider, got none", ruleExportedNoPermission)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("ContentProvider finding severity = %q, want high", f.Severity)
	}
	if f.MASVSID != "MASVS-PLATFORM-1" {
		t.Errorf("MASVSID = %q, want MASVS-PLATFORM-1", f.MASVSID)
	}
}

// -------------------------------------------------------------------------
// (c) Exported service WITH android:permission → NO finding
// -------------------------------------------------------------------------

func TestAnalyzeExposure_ExportedServiceWithPermission_NoFinding(t *testing.T) {
	meta := makeMetaWithComponents(
		nil,
		[]models.ManifestServiceInfo{
			{
				Name:       "com.example.AuthService",
				Exported:   true,
				Permission: "com.example.permission.USE_AUTH",
			},
		},
		nil, nil,
	)

	findings := AnalyzeExposure(meta)

	if f := findFindingByRule(findings, ruleExportedNoPermission); f != nil {
		t.Errorf("expected NO %q finding for permission-guarded exported service, got one: %+v", ruleExportedNoPermission, f)
	}
}

// -------------------------------------------------------------------------
// (d) Non-exported component → NO finding regardless of permission state
// -------------------------------------------------------------------------

func TestAnalyzeExposure_NonExportedComponent_NoFinding(t *testing.T) {
	meta := makeMetaWithComponents(
		[]models.ManifestActivityInfo{
			{Name: "com.example.InternalActivity", Exported: false, Permission: ""},
		},
		[]models.ManifestServiceInfo{
			{Name: "com.example.InternalService", Exported: false, Permission: ""},
		},
		[]models.ManifestReceiverInfo{
			{Name: "com.example.InternalReceiver", Exported: false, Permission: ""},
		},
		[]models.ManifestProviderInfo{
			{Name: "com.example.InternalProvider", Exported: false},
		},
	)

	findings := AnalyzeExposure(meta)

	if len(findings) != 0 {
		t.Errorf("expected zero findings for all non-exported components, got %d: %v", len(findings), findings)
	}
}

// -------------------------------------------------------------------------
// (e) Custom-scheme browsable deep-link → browsable-custom-scheme-deeplink
// -------------------------------------------------------------------------

func TestAnalyzeExposure_CustomSchemeBrowsableDeeplink(t *testing.T) {
	meta := makeMetaWithComponents(
		[]models.ManifestActivityInfo{
			{
				Name:       "com.example.DeepLinkActivity",
				Exported:   true,
				Permission: "com.example.permission.DEEPLINK", // guarded → no exported finding
				IntentFilters: []models.ManifestFilter{
					{
						Categories: []string{browsableCategory, "android.intent.category.DEFAULT"},
						Data: []models.ManifestFilterData{
							{Scheme: "myapp", Host: "open"},
						},
					},
				},
			},
		},
		nil, nil, nil,
	)

	findings := AnalyzeExposure(meta)

	f := findFindingByRule(findings, ruleBrowsableCustomScheme)
	if f == nil {
		t.Fatalf("expected finding %q for custom-scheme browsable deeplink, got none; all findings: %v", ruleBrowsableCustomScheme, findings)
	}
	if f.MASVSID != "MASVS-PLATFORM-1" {
		t.Errorf("MASVSID = %q, want MASVS-PLATFORM-1", f.MASVSID)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
	// Evidence must contain the scheme (never a secret; just scheme://host)
	if f.Evidence != "myapp://open" {
		t.Errorf("Evidence = %q, want myapp://open", f.Evidence)
	}
}

// -------------------------------------------------------------------------
// (f) https App Link WITHOUT android:autoVerify → app-link-no-autoverify
// -------------------------------------------------------------------------

func TestAnalyzeExposure_AppLinkMissingAutoVerify(t *testing.T) {
	meta := makeMetaWithComponents(
		[]models.ManifestActivityInfo{
			{
				Name:       "com.example.AppLinkActivity",
				Exported:   true,
				Permission: "com.example.permission.LINK", // guarded
				IntentFilters: []models.ManifestFilter{
					{
						Categories: []string{browsableCategory, "android.intent.category.DEFAULT"},
						AutoVerify: false, // missing autoVerify
						Data: []models.ManifestFilterData{
							{Scheme: "https", Host: "app.example.com"},
						},
					},
				},
			},
		},
		nil, nil, nil,
	)

	findings := AnalyzeExposure(meta)

	f := findFindingByRule(findings, ruleAppLinkNoAutoVerify)
	if f == nil {
		t.Fatalf("expected finding %q for App Link missing autoVerify, got none; all findings: %v", ruleAppLinkNoAutoVerify, findings)
	}
	if f.MASVSID != "MASVS-PLATFORM-1" {
		t.Errorf("MASVSID = %q, want MASVS-PLATFORM-1", f.MASVSID)
	}
	if f.Severity != models.SeverityLow {
		t.Errorf("Severity = %q, want low", f.Severity)
	}
	// Evidence should surface the host
	if f.Evidence != "app.example.com" {
		t.Errorf("Evidence = %q, want app.example.com", f.Evidence)
	}
}

// -------------------------------------------------------------------------
// (g) https App Link WITH android:autoVerify=true → NO finding
// -------------------------------------------------------------------------

func TestAnalyzeExposure_AppLinkWithAutoVerify_NoFinding(t *testing.T) {
	meta := makeMetaWithComponents(
		[]models.ManifestActivityInfo{
			{
				Name:       "com.example.VerifiedLinkActivity",
				Exported:   true,
				Permission: "com.example.permission.LINK",
				IntentFilters: []models.ManifestFilter{
					{
						Categories: []string{browsableCategory, "android.intent.category.DEFAULT"},
						AutoVerify: true, // correct: domain ownership verified
						Data: []models.ManifestFilterData{
							{Scheme: "https", Host: "app.example.com"},
						},
					},
				},
			},
		},
		nil, nil, nil,
	)

	findings := AnalyzeExposure(meta)

	if f := findFindingByRule(findings, ruleAppLinkNoAutoVerify); f != nil {
		t.Errorf("expected NO %q finding for App Link with autoVerify=true, got one: %+v", ruleAppLinkNoAutoVerify, f)
	}
	if f := findFindingByRule(findings, ruleBrowsableCustomScheme); f != nil {
		t.Errorf("expected NO %q finding for https App Link, got one: %+v", ruleBrowsableCustomScheme, f)
	}
}

// -------------------------------------------------------------------------
// Additional: http scheme is NOT flagged as custom scheme
// -------------------------------------------------------------------------

func TestAnalyzeExposure_HttpScheme_NotCustomScheme(t *testing.T) {
	meta := makeMetaWithComponents(
		[]models.ManifestActivityInfo{
			{
				Name:       "com.example.WebActivity",
				Exported:   true,
				Permission: "com.example.permission.WEB",
				IntentFilters: []models.ManifestFilter{
					{
						Categories: []string{browsableCategory},
						AutoVerify: false,
						Data: []models.ManifestFilterData{
							{Scheme: "http", Host: "www.example.com"},
						},
					},
				},
			},
		},
		nil, nil, nil,
	)

	findings := AnalyzeExposure(meta)

	// http without autoVerify → app-link-no-autoverify is only for https
	if f := findFindingByRule(findings, ruleAppLinkNoAutoVerify); f != nil {
		t.Errorf("http scheme should NOT produce %q finding (only https); got: %+v", ruleAppLinkNoAutoVerify, f)
	}
	// http is not a custom scheme → no custom-scheme finding
	if f := findFindingByRule(findings, ruleBrowsableCustomScheme); f != nil {
		t.Errorf("http scheme should NOT produce %q finding; got: %+v", ruleBrowsableCustomScheme, f)
	}
}

// -------------------------------------------------------------------------
// Additional: provider with BOTH readPermission + writePermission → guarded
// -------------------------------------------------------------------------

func TestAnalyzeExposure_ProviderBothReadWritePermission_NoFinding(t *testing.T) {
	meta := makeMetaWithComponents(
		nil, nil, nil,
		[]models.ManifestProviderInfo{
			{
				Name:            "com.example.SplitPermProvider",
				Exported:        true,
				Permission:      "",
				ReadPermission:  "com.example.permission.READ",
				WritePermission: "com.example.permission.WRITE",
			},
		},
	)

	findings := AnalyzeExposure(meta)

	if f := findFindingByRule(findings, ruleExportedNoPermission); f != nil {
		t.Errorf("expected NO finding for provider with both read+write permissions, got: %+v", f)
	}
}

// -------------------------------------------------------------------------
// Additional: provider with only readPermission (no writePermission) → flagged
// -------------------------------------------------------------------------

func TestAnalyzeExposure_ProviderOnlyReadPermission_Flagged(t *testing.T) {
	meta := makeMetaWithComponents(
		nil, nil, nil,
		[]models.ManifestProviderInfo{
			{
				Name:            "com.example.PartialProvider",
				Exported:        true,
				Permission:      "",
				ReadPermission:  "com.example.permission.READ",
				WritePermission: "",
			},
		},
	)

	findings := AnalyzeExposure(meta)

	f := findFindingByRule(findings, ruleExportedNoPermission)
	if f == nil {
		t.Fatalf("expected finding for provider with only readPermission (write is open), got none")
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
}

// -------------------------------------------------------------------------
// Additional: nil meta → no panic
// -------------------------------------------------------------------------

func TestAnalyzeExposure_NilMeta_NoPanic(t *testing.T) {
	findings := AnalyzeExposure(nil)
	if findings != nil {
		t.Errorf("expected nil return for nil meta, got %v", findings)
	}
}

// -------------------------------------------------------------------------
// Additional: empty manifest → zero findings
// -------------------------------------------------------------------------

func TestAnalyzeExposure_EmptyManifest_ZeroFindings(t *testing.T) {
	meta := &models.MetaDataModel{}
	findings := AnalyzeExposure(meta)
	if len(findings) != 0 {
		t.Errorf("expected zero findings for empty manifest, got %d: %v", len(findings), findings)
	}
}

// -------------------------------------------------------------------------
// Additional: providerIsPermissionGuarded logic
// -------------------------------------------------------------------------

func TestProviderIsPermissionGuarded(t *testing.T) {
	tests := []struct {
		name string
		p    models.ManifestProviderInfo
		want bool
	}{
		{
			name: "permission set",
			p:    models.ManifestProviderInfo{Permission: "com.example.PERM"},
			want: true,
		},
		{
			name: "both read+write set",
			p:    models.ManifestProviderInfo{ReadPermission: "r", WritePermission: "w"},
			want: true,
		},
		{
			name: "only read set",
			p:    models.ManifestProviderInfo{ReadPermission: "r"},
			want: false,
		},
		{
			name: "only write set",
			p:    models.ManifestProviderInfo{WritePermission: "w"},
			want: false,
		},
		{
			name: "none set",
			p:    models.ManifestProviderInfo{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := providerIsPermissionGuarded(tt.p); got != tt.want {
				t.Errorf("providerIsPermissionGuarded() = %v, want %v", got, tt.want)
			}
		})
	}
}

// -------------------------------------------------------------------------
// Additional: receiver with exported=true, no permission → medium severity
// -------------------------------------------------------------------------

func TestAnalyzeExposure_ExportedReceiverNoPermission(t *testing.T) {
	meta := makeMetaWithComponents(
		nil, nil,
		[]models.ManifestReceiverInfo{
			{Name: "com.example.PushReceiver", Exported: true, Permission: ""},
		},
		nil,
	)

	findings := AnalyzeExposure(meta)

	f := findFindingByRule(findings, ruleExportedNoPermission)
	if f == nil {
		t.Fatalf("expected finding %q for exported receiver without permission", ruleExportedNoPermission)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q, want medium (receiver)", f.Severity)
	}
}

// -------------------------------------------------------------------------
// Additional: custom scheme without BROWSABLE category → NOT flagged
// (only browsable deep-links are a hijack surface)
// -------------------------------------------------------------------------

func TestAnalyzeExposure_CustomSchemeNotBrowsable_NoFinding(t *testing.T) {
	meta := makeMetaWithComponents(
		[]models.ManifestActivityInfo{
			{
				Name:       "com.example.InternalSchemeActivity",
				Exported:   true,
				Permission: "com.example.permission.INTERNAL",
				IntentFilters: []models.ManifestFilter{
					{
						// No BROWSABLE category → not reachable from browser/OS dispatcher
						Categories: []string{"android.intent.category.DEFAULT"},
						Data: []models.ManifestFilterData{
							{Scheme: "internalapp", Host: "action"},
						},
					},
				},
			},
		},
		nil, nil, nil,
	)

	findings := AnalyzeExposure(meta)

	if f := findFindingByRule(findings, ruleBrowsableCustomScheme); f != nil {
		t.Errorf("non-browsable custom scheme should NOT produce %q finding; got: %+v", ruleBrowsableCustomScheme, f)
	}
}

// -------------------------------------------------------------------------
// Additional: all three finding types present in one meta
// -------------------------------------------------------------------------

func TestAnalyzeExposure_AllFindingTypesInOneMeta(t *testing.T) {
	meta := makeMetaWithComponents(
		[]models.ManifestActivityInfo{
			// exported without permission → exported-component-no-permission
			{Name: "com.example.OpenActivity", Exported: true, Permission: ""},
			// https app-link without autoVerify → app-link-no-autoverify
			{
				Name:       "com.example.LinkActivity",
				Exported:   true,
				Permission: "com.example.permission.LINK",
				IntentFilters: []models.ManifestFilter{
					{
						Categories: []string{browsableCategory},
						AutoVerify: false,
						Data:       []models.ManifestFilterData{{Scheme: "https", Host: "link.example.com"}},
					},
				},
			},
			// custom scheme browsable → browsable-custom-scheme-deeplink
			{
				Name:       "com.example.SchemeActivity",
				Exported:   true,
				Permission: "com.example.permission.SCHEME",
				IntentFilters: []models.ManifestFilter{
					{
						Categories: []string{browsableCategory},
						Data:       []models.ManifestFilterData{{Scheme: "myapp", Host: "open"}},
					},
				},
			},
		},
		nil, nil, nil,
	)

	findings := AnalyzeExposure(meta)

	rules := map[string]bool{}
	for _, f := range findings {
		rules[f.RuleID] = true
	}
	for _, want := range []string{ruleExportedNoPermission, ruleAppLinkNoAutoVerify, ruleBrowsableCustomScheme} {
		if !rules[want] {
			t.Errorf("expected finding with ruleId %q; rules seen: %v", want, rules)
		}
	}
}
