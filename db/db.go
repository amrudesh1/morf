package db

import (
	"morf/models"
	"os"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	// Connect to PHPMyAdmin database
	db, err := gorm.Open(mysql.Open(os.Getenv("DATABASE_URL")), &gorm.Config{})

	if err != nil {
		panic("failed to connect database")
	}
	// Migrate the schema
	db.AutoMigrate(&models.Secrets{})
	DB = db

}
func InsertSecrets(secret models.Secrets, db *gorm.DB) {
	db.Create(&secret)
}

func GetSecrets(db *gorm.DB) []models.Secrets {
	var secrets []models.Secrets
	db.Find(&secrets)
	return secrets
}

func GetLastSecret(db *gorm.DB) models.Secrets {
	var secret models.Secrets
	db.Last(&secret)
	return secret
}
