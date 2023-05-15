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
*/package models

import (
	"github.com/lib/pq"
)

type PackageDataModel struct {
	PackageDataID     uint
	APKHash           string
	PackageName       string
	VersionCode       string
	VersionName       string
	CompileSdkVersion string
	SdkVersion        string
	TargetSdk         string
	SupportScreens    pq.StringArray `gorm:"type:varchar(100)"`
	Densities         pq.StringArray `gorm:"type:varchar(100)"`
	NativeCode        pq.StringArray `gorm:"type:varchar(100)"`
}
