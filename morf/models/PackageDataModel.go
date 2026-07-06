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

package models

// PackageDataModel represents package information extracted from an APK.
//
// NOTE: PackageDataModel duplicates models.PackageData (see PackageData.go). Both
// carry the same field set (APKHash, PackageName, VersionCode, VersionName,
// CompileSdkVersion, SdkVersion, TargetSdk, MinSDK, SupportScreens, Densities,
// NativeCode). PackageDataModel is the legacy representation embedded into the
// Secrets table (no standalone gorm table); PackageData is the normalized
// standalone table. They are maintained in parallel during the normalization
// migration. Once the migration completes, PackageDataModel and the old Secrets
// table should be retired, leaving PackageData as the single source of truth.
type PackageDataModel struct {
	PackageDataID     int             `json:"packageDataId"`
	APKHash           string          `json:"apkHash"`
	PackageName       string          `json:"packageName"`
	VersionCode       string          `json:"versionCode"`
	VersionName       string          `json:"versionName"`
	CompileSdkVersion string          `json:"compileSdkVersion"`
	SdkVersion        string          `json:"sdkVersion"`
	TargetSdk         string          `json:"targetSdk"`
	MinSDK            string          `json:"minSdk"`
	SupportScreens    JSONStringArray `gorm:"type:json" json:"supportScreens"`
	Densities         JSONStringArray `gorm:"type:json" json:"densities"`
	NativeCode        JSONStringArray `gorm:"type:json" json:"nativeCode"`
}
