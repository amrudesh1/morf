package models

import (
	"gorm.io/gorm"
)

type Secrets struct {
	gorm.Model
	FileName         string
	APKHash          string
	APKVersion       string
	SecretModel      string
	Metadata         MetaDataModel    `gorm:"embedded;"`
	PackageDataModel PackageDataModel `gorm:"embedded;"`
}

type SecretModel struct {
	SecretID     uint
	Type         string
	LineNo       int
	FileLocation string
	SecretType   string
	SecretString string
}
