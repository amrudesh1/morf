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

package response

import (
	"encoding/json"

	"morf/models"

	"github.com/gin-gonic/gin"
)

// IOSMetadataHandler is the iOS analogue of MetadataHandler: it serializes an
// IOSMetadata row into the result envelope's "data" object. The Android
// MetadataHandler injects activities/services/… ; this injects the iOS-specific
// fields (bundle identity, architectures, encryption, and the JSON-typed lists
// and maps extracted from the Info.plist / Mach-O / provisioning profile).
type IOSMetadataHandler struct {
	metadata models.IOSMetadata
}

// NewIOSMetadataHandler creates a new instance of IOSMetadataHandler.
func NewIOSMetadataHandler(metadata models.IOSMetadata) *IOSMetadataHandler {
	return &IOSMetadataHandler{metadata: metadata}
}

// TransformMetadata builds the iOS metadata response fragment. The JSON-typed
// IOSMetadata columns (Architectures, URLSchemes, Entitlements, Frameworks,
// ATSExceptions) are stored as marshalled JSON strings; they are decoded here
// via decodeJSONField so the envelope carries real JSON arrays/objects rather
// than opaque escaped strings. A column that is empty or fails to parse is
// emitted as JSON null, never as a raw string, so the shape stays stable.
func (h *IOSMetadataHandler) TransformMetadata() gin.H {
	return gin.H{
		"platform":         "ios",
		"bundleIdentifier": h.metadata.BundleIdentifier,
		"bundleVersion":    h.metadata.BundleVersion,
		"deploymentTarget": h.metadata.DeploymentTarget,
		"executableName":   h.metadata.ExecutableName,
		"isEncrypted":      h.metadata.IsEncrypted,
		"architectures":    decodeJSONField(h.metadata.Architectures),
		"urlSchemes":       decodeJSONField(h.metadata.URLSchemes),
		"entitlements":     decodeJSONField(h.metadata.Entitlements),
		"frameworks":       decodeJSONField(h.metadata.Frameworks),
		"atsExceptions":    decodeJSONField(h.metadata.ATSExceptions),
	}
}

// AddMetadataToResponse merges the iOS metadata fragment into an existing
// response's "data" object, mirroring MetadataHandler.AddMetadataToResponse so
// the worker result path is handler-symmetric across platforms.
func (h *IOSMetadataHandler) AddMetadataToResponse(response gin.H) {
	if data, ok := response["data"].(gin.H); ok {
		for k, v := range h.TransformMetadata() {
			data[k] = v
		}
	}
}

// decodeJSONField unmarshals a JSON-string column into a generic value so it is
// re-emitted as structured JSON. An empty column or an unparseable value yields
// nil (JSON null) rather than leaking the raw string into the envelope.
func decodeJSONField(s string) interface{} {
	if s == "" {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return v
}
