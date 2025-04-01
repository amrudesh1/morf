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

// PackageInfo defines the interface for package information
type PackageInfo interface {
	GetPackageName() string
	GetVersion() string
	GetMinSDK() string
	GetTargetSDK() string
}

// PackageDataModel represents package information extracted from an APK
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

// Implement the PackageInfo interface
func (p PackageDataModel) GetPackageName() string {
	return p.PackageName
}

func (p PackageDataModel) GetVersion() string {
	return p.VersionName
}

func (p PackageDataModel) GetMinSDK() string {
	return p.MinSDK
}

func (p PackageDataModel) GetTargetSDK() string {
	return p.TargetSdk
}
