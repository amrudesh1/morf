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

package cmd

import (
	"fmt"
	"strings"

	"morf/auth"
	"morf/db"
	"morf/models"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// GetAPIKeyCmd returns the `apikey` command tree (MED-scopes key-management
// surface). It provisions the API keys the auth middleware validates and the
// scopes that the opt-in RequireScope enforcement (MORF_ENFORCE_SCOPES) checks.
// Without this surface there was no way to mint a scoped key, so scope
// enforcement could not be turned on safely; this closes that gap. Keys are
// stored HASHED — the plaintext is shown exactly once, at creation.
func GetAPIKeyCmd() *cobra.Command {
	apiKeyCmd := &cobra.Command{
		Use:   "apikey",
		Short: "Manage API keys (create, list, revoke)",
		Long:  "Provision and manage the API keys used by MORF's opt-in authentication and scope enforcement.",
	}

	apiKeyCmd.AddCommand(apiKeyCreateCmd(), apiKeyListCmd(), apiKeyRevokeCmd())
	return apiKeyCmd
}

func requireDB() {
	db.InitDB()
	if !db.DatabaseRequired || db.GormDB == nil {
		log.Fatal("Database not available. Set DATABASE_URL.")
	}
}

func apiKeyCreateCmd() *cobra.Command {
	var name, scopesCSV string
	var rateLimit int
	c := &cobra.Command{
		Use:   "create",
		Short: "Create a new API key and print the secret once",
		Run: func(cmd *cobra.Command, args []string) {
			if strings.TrimSpace(name) == "" {
				log.Fatal("--name is required")
			}
			requireDB()
			plain, hashed := auth.GenerateAPIKey()
			scopes := parseScopes(scopesCSV)
			key := &models.APIKey{
				Key:       hashed,
				Name:      name,
				Scopes:    scopes,
				RateLimit: rateLimit,
				IsActive:  true,
			}
			if err := db.GormDB.Create(key).Error; err != nil {
				log.Fatalf("Failed to create API key: %v", err)
			}
			fmt.Println("API key created. Store this secret NOW — it will not be shown again:")
			fmt.Printf("  key:    %s\n", plain)
			fmt.Printf("  id:     %d\n", key.ID)
			fmt.Printf("  name:   %s\n", name)
			fmt.Printf("  scopes: %s\n", strings.Join([]string(scopes), ","))
		},
	}
	c.Flags().StringVar(&name, "name", "", "Human-readable key name (required)")
	c.Flags().StringVar(&scopesCSV, "scopes", "", "Comma-separated scopes (e.g. scan:write); use * for all")
	c.Flags().IntVar(&rateLimit, "rate-limit", 100, "Requests per hour for this key")
	return c
}

func apiKeyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List API keys (metadata only; never the secret)",
		Run: func(cmd *cobra.Command, args []string) {
			requireDB()
			var keys []models.APIKey
			if err := db.GormDB.Find(&keys).Error; err != nil {
				log.Fatalf("Failed to list API keys: %v", err)
			}
			if len(keys) == 0 {
				fmt.Println("No API keys.")
				return
			}
			fmt.Printf("%-5s %-24s %-7s %-8s %s\n", "ID", "NAME", "ACTIVE", "RATE/HR", "SCOPES")
			for _, k := range keys {
				fmt.Printf("%-5d %-24s %-7t %-8d %s\n", k.ID, k.Name, k.IsActive, k.RateLimit, strings.Join([]string(k.Scopes), ","))
			}
		},
	}
}

func apiKeyRevokeCmd() *cobra.Command {
	var id uint
	c := &cobra.Command{
		Use:   "revoke",
		Short: "Deactivate an API key by ID",
		Run: func(cmd *cobra.Command, args []string) {
			if id == 0 {
				log.Fatal("--id is required")
			}
			requireDB()
			res := db.GormDB.Model(&models.APIKey{}).Where("id = ?", id).Update("is_active", false)
			if res.Error != nil {
				log.Fatalf("Failed to revoke API key: %v", res.Error)
			}
			if res.RowsAffected == 0 {
				log.Fatalf("No API key with id %d", id)
			}
			fmt.Printf("API key %d deactivated. Cached validations expire within the auth cache TTL.\n", id)
		},
	}
	c.Flags().UintVar(&id, "id", 0, "ID of the API key to revoke (required)")
	return c
}

// parseScopes splits a comma-separated scope list into a normalized slice.
func parseScopes(csv string) models.JSONStringArray {
	parts := strings.Split(csv, ",")
	out := make(models.JSONStringArray, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
