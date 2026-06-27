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

import (
	"morf/models"
	"os"
	"strings"
	"testing"
)

func TestParseManifestFromSample(t *testing.T) {
	// Read the sample XML tree
	xmlTree, err := os.ReadFile("sample_xmltree.txt")
	if err != nil {
		t.Fatalf("Failed to read sample XML tree: %v", err)
	}

	// Manifest is split into lines once; extractors now take []string
	// (single-walk refactor, finding SCAN-10).
	lines := strings.Split(string(xmlTree), "\n")

	// Create a metadata model
	metadata := &models.MetaDataModel{}
	metadata.AndroidManifest.UsesTargetSdkVersion = "34" // Android 14

	// Extract activities
	activities := extractActivities(lines, 34)
	t.Logf("Found %d activities", len(activities))

	// Expected activity export states
	expectedActivities := map[string]bool{
		"com.dreamplug.fabrik.ui.main.MainActivity":                         false, // No explicit export, no intent filters
		"com.dreamplug.androidapp.SplashActivity":                           true,  // Has explicit exported=0xffffffff
		"com.dreamplug.processrestart.PhoenixActivity":                      false, // Has explicit exported=0x0
		"com.dreamplug.androidapp.deeplink.DeeplinkActivity":                true,  // Has explicit exported=0xffffffff
		"com.dreamplug.androidapp.UpiIntentActivity":                        true,  // Has explicit exported=0xffffffff
		"com.google.android.gms.auth.api.signin.internal.SignInHubActivity": false, // Has explicit exported=0x0
	}

	// Check activities
	for _, activity := range activities {
		if expectedExported, exists := expectedActivities[activity.Name]; exists {
			if activity.Exported != expectedExported {
				t.Errorf("Activity %s: expected exported=%v, got exported=%v",
					activity.Name, expectedExported, activity.Exported)
			} else {
				t.Logf("Activity %s: correctly exported=%v", activity.Name, activity.Exported)
			}
		}
	}

	// Extract services
	services := extractServices(lines, 34)
	t.Logf("Found %d services", len(services))

	// Expected service export states
	expectedServices := map[string]bool{
		"com.dreamplug.androidapp.service.CredFirebaseMessagingService": false, // Has explicit exported=0x0
		"com.dreamplug.tapcore.nfc.NfCApduWrapperService":               true,  // Has explicit exported=0xffffffff
		"androidx.work.impl.background.systemjob.SystemJobService":      true,  // Has explicit exported=0xffffffff
	}

	// Check services
	for _, service := range services {
		if expectedExported, exists := expectedServices[service.Name]; exists {
			if service.Exported != expectedExported {
				t.Errorf("Service %s: expected exported=%v, got exported=%v",
					service.Name, expectedExported, service.Exported)
			} else {
				t.Logf("Service %s: correctly exported=%v", service.Name, service.Exported)
			}
		}
	}

	// Extract receivers
	receivers := extractReceivers(lines, 34)
	t.Logf("Found %d receivers", len(receivers))

	// Expected receiver export states
	expectedReceivers := map[string]bool{
		"com.appsflyer.SingleInstallBroadcastReceiver":                         true,  // Has explicit exported=0xffffffff
		"com.dreamplug.androidapp.AppUpdateReceiver":                           true,  // Has explicit exported=0xffffffff
		"com.dreamplug.androidapp.service.NotificationDismissedReceiver":       false, // No explicit export, no intent filters
		"com.dreamplug.fabrik.ui.cards.unbilled.widget.UnBilledWidgetProvider": true,  // Has explicit exported=0xffffffff
	}

	// Check receivers
	for _, receiver := range receivers {
		if expectedExported, exists := expectedReceivers[receiver.Name]; exists {
			if receiver.Exported != expectedExported {
				t.Errorf("Receiver %s: expected exported=%v, got exported=%v",
					receiver.Name, expectedExported, receiver.Exported)
			} else {
				t.Logf("Receiver %s: correctly exported=%v", receiver.Name, receiver.Exported)
			}
		}
	}

	// Extract providers
	providers := extractProviders(lines, 34)
	t.Logf("Found %d providers", len(providers))

	// Expected provider export states
	expectedProviders := map[string]bool{
		"androidx.startup.InitializationProvider":                   false, // Has explicit exported=0x0
		"androidx.core.content.FileProvider":                        false, // Has explicit exported=0x0 with grantUriPermissions=true
		"com.google.firebase.provider.FirebaseInitProvider":         false, // Has explicit exported=0x0
		"com.freshchat.consumer.sdk.provider.FreshchatInitProvider": false, // Has explicit exported=0x0
	}

	// Check providers
	for _, provider := range providers {
		if expectedExported, exists := expectedProviders[provider.Name]; exists {
			if provider.Exported != expectedExported {
				t.Errorf("Provider %s: expected exported=%v, got exported=%v",
					provider.Name, expectedExported, provider.Exported)
			} else {
				t.Logf("Provider %s: correctly exported=%v", provider.Name, provider.Exported)
			}
		}
	}

	// Check for deeplinks
	deeplinkCount := 0
	for _, activity := range activities {
		for _, filter := range activity.IntentFilters {
			for _, data := range filter.Data {
				if data.Scheme != "" {
					deeplinkCount++
					t.Logf("Found deeplink in %s: scheme=%s, host=%s, path=%s",
						activity.Name, data.Scheme, data.Host, data.Path)
				}
			}
		}
	}
	t.Logf("Total deeplinks found: %d", deeplinkCount)
}

func TestIsHexValueTrue(t *testing.T) {
	tests := []struct {
		name     string
		hexValue string
		want     bool
	}{
		{"True value", "0xffffffff", true},
		{"False value", "0x0", false},
		{"Invalid hex", "0x1", false},
		{"Empty string", "", false},
		{"Non-hex string", "true", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHexValueTrue(tt.hexValue); got != tt.want {
				t.Errorf("isHexValueTrue(%q) = %v, want %v", tt.hexValue, got, tt.want)
			}
		})
	}
}
