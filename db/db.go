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
*/package db

import (
	"fmt"
	"os"

	"github.com/amrudesh1/morf/models"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	// Connect to PHPMyAdmin database
	db, err := gorm.Open(mysql.Open(os.Getenv("DATABASE_URL")), &gorm.Config{})
	fmt.Println("Database URL:", os.Getenv("DATABASE_URL"))

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
