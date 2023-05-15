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

import "github.com/lib/pq"

type MetaDataModel struct {
	FileName        string `json:"fileName"`
	FileSize        int    `json:"fileSize"`
	DexSize         int    `json:"dexSize"`
	ArscSize        int    `json:"arscSize"`
	AndroidManifest struct {
		PackageName                string         `json:"packageName"`
		VersionCode                string         `json:"versionCode"`
		NumberOfActivities         int            `json:"numberOfActivities"`
		NumberOfServices           int            `json:"numberOfServices"`
		NumberOfContentProviders   int            `json:"numberOfContentProviders"`
		NumberOfBroadcastReceivers int            `json:"numberOfBroadcastReceivers"`
		NamesOfActivities          pq.StringArray `gorm:"type:text;"`
		NamesOfServices            pq.StringArray `gorm:"type:text;"`
		NamesOfContentProviders    pq.StringArray `gorm:"type:text;"`
		NamesOfBroadcastReceivers  pq.StringArray `gorm:"type:text;"`
		UsesPermissions            pq.StringArray `gorm:"type:text;"`
		UsesLibrary                pq.StringArray `gorm:"type:text;"`
		UsesFeature                pq.StringArray `gorm:"type:text;"`
		Permissions                pq.StringArray `gorm:"type:text;"`
		PermissionsProtectionLevel pq.StringArray `gorm:"type:text;"`
		UsesMinSdkVersion          string         `json:"usesMinSdkVersion"`
		UsesTargetSdkVersion       string         `json:"usesTargetSdkVersion"`
		UsesMaxSdkVersion          string         `json:"usesMaxSdkVersion"`
	} `gorm:"embedded;" json:"androidManifest"`
	CertificateDatas struct {
		FileName         string `json:"fileName"`
		SignAlgorithm    string `json:"signAlgorithm"`
		SignAlgorithmOID string `json:"signAlgorithmOID"`
		StartDate        string `json:"startDate"`
		EndDate          string `json:"endDate"`
		PublicKeyMd5     string `json:"publicKeyMd5"`
		CertBase64Md5    string `json:"certBase64Md5"`
		CertMd5          string `json:"certMd5"`
		Version          int    `json:"version"`
		IssuerName       string `json:"issuerName"`
		SubjectName      string `json:"subjectName"`
	} `gorm:"embedded;"`
	ResourceData struct {
		Locale                  pq.StringArray `gorm:"type:text;" json:"locale"`
		NumberOfStringResource  int            `json:"numberOfStringResource"`
		PngDrawables            int            `json:"pngDrawables"`
		NinePatchDrawables      int            `json:"ninePatchDrawables"`
		JpgDrawables            int            `json:"jpgDrawables"`
		GifDrawables            int            `json:"gifDrawables"`
		XMLDrawables            int            `json:"xmlDrawables"`
		DifferentDrawables      int            `json:"differentDrawables"`
		LdpiDrawables           int            `json:"ldpiDrawables"`
		MdpiDrawables           int            `json:"mdpiDrawables"`
		HdpiDrawables           int            `json:"hdpiDrawables"`
		XhdpiDrawables          int            `json:"xhdpiDrawables"`
		XxhdpiDrawables         int            `json:"xxhdpiDrawables"`
		XxxhdpiDrawables        int            `json:"xxxhdpiDrawables"`
		NodpiDrawables          int            `json:"nodpiDrawables"`
		TvdpiDrawables          int            `json:"tvdpiDrawables"`
		UnspecifiedDpiDrawables int            `json:"unspecifiedDpiDrawables"`
		RawResources            int            `json:"rawResources"`
		Menu                    int            `json:"menu"`
		Layouts                 int            `json:"layouts"`
		DifferentLayouts        int            `json:"differentLayouts"`
	} `gorm:"embedded;" json:"resourceData"`
	FileDigest struct {
	} `gorm:"embedded;" json:"fileDigest" `
}
