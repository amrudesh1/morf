package models

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
