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

import (
	"gorm.io/gorm"
)

// PackageData represents normalized package data (one per unique APK hash)
type PackageData struct {
	gorm.Model
	APKHash           string          `json:"apkHash" gorm:"column:apk_hash;size:255;uniqueIndex:idx_apk_hash;not null"`
	PackageName       string          `json:"packageName" gorm:"column:package_name;size:255;index:idx_package_name;not null"`
	VersionCode       string          `json:"versionCode" gorm:"column:version_code"`
	VersionName       string          `json:"versionName" gorm:"column:version_name"`
	CompileSdkVersion string          `json:"compileSdkVersion" gorm:"column:compile_sdk_version"`
	SdkVersion        string          `json:"sdkVersion" gorm:"column:sdk_version"`
	TargetSdk         string          `json:"targetSdk" gorm:"column:target_sdk"`
	MinSDK            string          `json:"minSdk" gorm:"column:min_sdk"`
	SupportScreens    JSONStringArray `json:"supportScreens" gorm:"type:json;column:support_screens"`
	Densities         JSONStringArray `json:"densities" gorm:"type:json;column:densities"`
	NativeCode        JSONStringArray `json:"nativeCode" gorm:"type:json;column:native_code"`
}

// TableName specifies the table name for PackageData
func (PackageData) TableName() string {
	return "package_data"
}

// Implement PackageInfo interface
func (p PackageData) GetPackageName() string {
	return p.PackageName
}

func (p PackageData) GetVersion() string {
	return p.VersionName
}

func (p PackageData) GetMinSDK() string {
	return p.MinSDK
}

func (p PackageData) GetTargetSDK() string {
	return p.TargetSdk
}
