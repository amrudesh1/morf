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

package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"morf/models"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"gorm.io/gorm"
)

// isAllowedJiraHost reports whether host is exactly the approved Jira Cloud
// domain or a true dotted subdomain of it. Jira Cloud tenants live under
// *.atlassian.net (NOT atlassian.com). This is stricter than a bare HasSuffix
// check, which "evilatlassian.net" would wrongly pass.
func isAllowedJiraHost(host string) bool {
	h := strings.ToLower(host)
	return h == "atlassian.net" || strings.HasSuffix(h, ".atlassian.net")
}

// validateJiraURL parses jiraURL, enforces an https-only scheme, requires the
// host to be an approved Jira Cloud domain (exact/dotted-suffix match), and
// resolves the host to reject any private/loopback/link-local/metadata
// destination so a leaked token cannot be used to reach internal hosts
// (SSRF / DNS-rebinding defence). It reuses isDisallowedIP from webhook.go.
func validateJiraURL(jiraURL string) error {
	parsedURL, err := url.Parse(jiraURL)
	if err != nil {
		return fmt.Errorf("invalid JIRA URL: %w", err)
	}
	if parsedURL.Scheme != "https" {
		return fmt.Errorf("JIRA URL must use https scheme")
	}
	host := parsedURL.Hostname()
	if !isAllowedJiraHost(host) {
		return fmt.Errorf("JIRA URL is not from an approved atlassian.net domain")
	}
	// Resolve and reject internal addresses (SSRF protection).
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedIP(ip) {
			return fmt.Errorf("JIRA URL resolves to a disallowed IP (SSRF protection)")
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve JIRA host: %w", err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("JIRA host did not resolve to any address")
	}
	for _, ip := range ips {
		if isDisallowedIP(ip) {
			return fmt.Errorf("JIRA URL resolves to a disallowed IP (SSRF protection)")
		}
	}
	return nil
}

// CheckDuplicateInDB checks if an APK has already been scanned using normalized schema.
// All associations (PackageData + SecretFindings + Activities + Services +
// ContentProviders + BroadcastReceivers) are loaded in a single Preload chain,
// matching the pattern used by db.GetSecrets, instead of five sequential per-
// association Find calls.
func CheckDuplicateInDB(db *gorm.DB, apkPath string) (bool, string) {
	// Check if database connection is valid
	if db == nil {
		log.Warn("Database connection is nil, skipping duplicate check")
		return false, ""
	}

	apkhash := ExtractHash(apkPath)

	// Single Preload chain: one set of round-trips (main query + one per
	// association) instead of two top-level Finds followed by five child Finds.
	var secret models.Secret
	if err := db.
		Preload("PackageData").
		Preload("SecretFindings").
		Preload("Activities").
		Preload("Services").
		Preload("ContentProviders").
		Preload("BroadcastReceivers").
		Where("apk_hash = ?", apkhash).
		Order("created_at DESC").
		First(&secret).Error; err != nil {
		log.Infof("APK hash %s not found in database", apkhash)
		return false, ""
	}

	// Reconstruct old Secrets model format for backward compatibility.
	// Associations are already populated by the Preload chain above.
	secretModelArray := make([]models.SecretModel, 0, len(secret.SecretFindings))
	for _, finding := range secret.SecretFindings {
		secretModelArray = append(secretModelArray, models.SecretModel{
			Type:             finding.Type,
			LineNo:           finding.LineNo,
			FileLocation:     finding.FileLocation,
			SecretType:       finding.SecretType,
			SecretString:     finding.SecretString,
			SecretConfidence: finding.SecretConfidence,
		})
	}

	// Parse metadata JSON
	var metadata models.MetaDataModel
	if err := json.Unmarshal([]byte(secret.Metadata), &metadata); err != nil {
		log.Warnf("Failed to unmarshal metadata: %v", err)
		metadata = models.MetaDataModel{}
	}

	// Convert activities
	activitiesArray := make([]models.ManifestActivityInfo, 0, len(secret.Activities))
	for _, activity := range secret.Activities {
		var intentFilters []models.ManifestFilter
		if activity.IntentFilters != "" {
			json.Unmarshal([]byte(activity.IntentFilters), &intentFilters)
		}
		activitiesArray = append(activitiesArray, models.ManifestActivityInfo{
			Name:          activity.Name,
			Exported:      activity.Exported,
			IntentFilters: intentFilters,
		})
	}

	// Convert services
	servicesArray := make([]models.ManifestServiceInfo, 0, len(secret.Services))
	for _, service := range secret.Services {
		var intentFilters []models.ManifestFilter
		if service.IntentFilters != "" {
			json.Unmarshal([]byte(service.IntentFilters), &intentFilters)
		}
		servicesArray = append(servicesArray, models.ManifestServiceInfo{
			Name:          service.Name,
			Exported:      service.Exported,
			IntentFilters: intentFilters,
		})
	}

	// Convert content providers
	providersArray := make([]models.ManifestProviderInfo, 0, len(secret.ContentProviders))
	for _, provider := range secret.ContentProviders {
		var authorities []string
		if provider.Authorities != "" {
			json.Unmarshal([]byte(provider.Authorities), &authorities)
		}
		providersArray = append(providersArray, models.ManifestProviderInfo{
			Name:                provider.Name,
			Exported:            provider.Exported,
			Authorities:         authorities,
			GrantUriPermissions: provider.GrantUriPermissions,
		})
	}

	// Convert broadcast receivers
	receiversArray := make([]models.ManifestReceiverInfo, 0, len(secret.BroadcastReceivers))
	for _, receiver := range secret.BroadcastReceivers {
		var intentFilters []models.ManifestFilter
		if receiver.IntentFilters != "" {
			json.Unmarshal([]byte(receiver.IntentFilters), &intentFilters)
		}
		receiversArray = append(receiversArray, models.ManifestReceiverInfo{
			Name:          receiver.Name,
			Exported:      receiver.Exported,
			IntentFilters: intentFilters,
		})
	}

	// Reconstruct Secrets model using the preloaded PackageData instead of
	// a separate by-hash lookup.
	oldSecret := models.Secrets{
		FileName:    secret.FileName,
		APKHash:     secret.APKHash,
		APKVersion:  secret.APKVersion,
		SecretModel: models.SecretModelArray(secretModelArray),
		Metadata:    metadata,
		PackageDataModel: models.PackageDataModel{
			APKHash:           secret.PackageData.APKHash,
			PackageName:       secret.PackageData.PackageName,
			VersionCode:       secret.PackageData.VersionCode,
			VersionName:       secret.PackageData.VersionName,
			CompileSdkVersion: secret.PackageData.CompileSdkVersion,
			SdkVersion:        secret.PackageData.SdkVersion,
			TargetSdk:         secret.PackageData.TargetSdk,
			MinSDK:            secret.PackageData.MinSDK,
			SupportScreens:    secret.PackageData.SupportScreens,
			Densities:         secret.PackageData.Densities,
			NativeCode:        secret.PackageData.NativeCode,
		},
		Activities:         models.JSONComponentArray[models.ManifestActivityInfo](activitiesArray),
		Services:           models.JSONComponentArray[models.ManifestServiceInfo](servicesArray),
		ContentProviders:   models.JSONComponentArray[models.ManifestProviderInfo](providersArray),
		BroadcastReceivers: models.JSONComponentArray[models.ManifestReceiverInfo](receiversArray),
	}

	jsonData, err := json.Marshal(oldSecret)
	if err != nil {
		log.Error("Error marshaling secret data:", err)
		return true, ""
	}

	log.Infof("File %s found in database", secret.FileName)
	return true, string(jsonData)
}

func CreateSecretModel(apkPath string, packageModel models.PackageDataModel, metadata models.MetaDataModel, scanner_data []models.SecretModel, secretData []byte) models.Secrets {
	// Store component data in the database columns
	secretModel := models.Secrets{
		FileName:           apkPath,
		APKHash:            packageModel.APKHash,
		APKVersion:         packageModel.VersionName,
		SecretModel:        models.SecretModelArray(scanner_data),
		PackageDataModel:   packageModel,
		Activities:         metadata.AndroidManifest.Activities,
		Services:           metadata.AndroidManifest.Services,
		ContentProviders:   metadata.AndroidManifest.ContentProviders,
		BroadcastReceivers: metadata.AndroidManifest.BroadcastReceivers,
	}

	// Clear component arrays from metadata to avoid duplication
	metadata.AndroidManifest.Activities = nil
	metadata.AndroidManifest.Services = nil
	metadata.AndroidManifest.ContentProviders = nil
	metadata.AndroidManifest.BroadcastReceivers = nil
	secretModel.Metadata = metadata

	return secretModel
}

// CookJiraComment prepares a comment for a JIRA ticket
func CookJiraComment(jiraModel models.JiraModel, secret models.Secrets, ctx *gin.Context) string {
	if len(parseJiraMessage(secret)) == 0 {
		return ""
	} else {
		for _, message := range parseJiraMessage(secret) {
			commentToJira(jiraModel, message)
		}
	}

	return "Commented on Jira ticket"
}

func parseJiraMessage(secrets models.Secrets) []string {
	secretModel := secrets.SecretModel

	var messages []string
	var currentMessage string

	currentMessage = "h2. MORF - Mobile Reconnisance Framework\n" +
		"h4. APK Name: " + secrets.FileName + "\n" +
		"h4. App Version: " + secrets.PackageDataModel.VersionName + "\n" +
		"h4. Package Name: " + secrets.PackageDataModel.PackageName + "\n" +
		"h4. SHA1: " + secrets.APKHash + "\n" +
		"h4. Secrets in APK:\n" +
		"----------------\n" +
		strconv.Itoa(len(secretModel)) + " secrets found\n" +
		"----------------\n"

	for _, value := range []models.SecretModel(secretModel) {
		heading := value.Type
		headingMarkup := fmt.Sprintf("\n === %s ===\n", heading)
		secretEntry := "{noformat}" +
			headingMarkup +
			"Secret Value: " + value.SecretString + "\n" +
			"Line No: " + strconv.Itoa(value.LineNo) + "\n" +
			"File Location: " + value.FileLocation + "\n" +
			"{noformat}"

		if len(currentMessage)+len(secretEntry) > 32767 { // Jira has a 32,767 character limit per comment
			messages = append(messages, currentMessage)
			currentMessage = secretEntry
		} else {
			currentMessage += secretEntry
		}
	}

	if currentMessage != "{noformat}" {
		messages = append(messages, currentMessage)
	}

	return messages
}

// commentToJira posts a comment to a JIRA ticket
// Security improvements:
// - Validates JIRA URL is from allowed domain (SSRF protection)
// - Sanitizes URL to prevent SSRF
// - Uses Basic Auth in headers (already correct)
// - Adds timeout on JIRA API calls (30 seconds)
func commentToJira(jiraModel models.JiraModel, message string) string {
	// Get JIRA base URL from environment or use provided host
	jiraBaseURL := os.Getenv("JIRA_LINK")
	if jiraBaseURL == "" && jiraModel.JiraHost != "" {
		jiraBaseURL = jiraModel.JiraHost
	}

	if jiraBaseURL == "" {
		log.Error("JIRA_LINK environment variable not set and no host provided")
		return "JIRA_LINK not configured"
	}

	// Validate and sanitize JIRA URL (SSRF protection)
	_, err := url.Parse(jiraBaseURL)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
			"url":   maskURLForLogging(jiraBaseURL),
		}).Error("Invalid JIRA base URL")
		return "Invalid JIRA URL"
	}

	// Sanitize ticket ID to prevent path traversal
	ticketID := sanitizeTicketID(jiraModel.Ticket_id)
	if ticketID == "" {
		log.Error("Invalid ticket ID")
		return "Invalid ticket ID"
	}

	// Construct JIRA API URL
	jiraURL := fmt.Sprintf("%s/rest/api/2/issue/%s/comment", jiraBaseURL, ticketID)

	// Validate the final URL: https-only scheme, strict atlassian.net allowlist,
	// and reject hosts that resolve to private/loopback/link-local/metadata IPs
	// (SSRF / DNS-rebinding protection). Reuses isDisallowedIP from webhook.go.
	if err := validateJiraURL(jiraURL); err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
			"url":   maskURLForLogging(jiraURL),
		}).Error("JIRA URL failed SSRF validation")
		return "JIRA URL not from allowed domain"
	}

	// Prepare request body
	finalBody := map[string]string{"body": message}
	finalBodyJSON, err := json.Marshal(finalBody)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("Failed to marshal JIRA comment body")
		return "Failed to prepare comment"
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", jiraURL, bytes.NewBuffer(finalBodyJSON))
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("Failed to create JIRA request")
		return "Failed to create request"
	}

	// Set headers - credentials already in header (Basic Auth)
	req.Header.Set("Content-Type", "application/json")

	// Validate JiraToken format (should be base64 encoded for Basic Auth)
	if jiraModel.JiraToken == "" {
		log.Error("JIRA token is empty")
		return "JIRA token required"
	}

	// If token is not already base64 encoded, encode it
	// Basic Auth format: base64(username:password)
	token := jiraModel.JiraToken
	if !isBase64Encoded(token) {
		// Assume it's username:password format
		token = base64.StdEncoding.EncodeToString([]byte(token))
	}

	req.Header.Set("Authorization", "Basic "+token)

	// Create HTTP client with timeout (30 seconds)
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	log.WithFields(log.Fields{
		"jira_url":  maskURLForLogging(jiraURL),
		"ticket_id": ticketID,
	}).Info("Posting comment to JIRA")

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("Failed to post comment to JIRA")
		return "Request failed"
	}

	defer resp.Body.Close()

	log.WithFields(log.Fields{
		"status_code": resp.StatusCode,
		"status":      resp.Status,
	}).Info("JIRA API response")

	if resp.StatusCode == 201 {
		log.Info("Successfully commented on JIRA ticket")
		SlackRespond(jiraModel, models.SlackData{SlackToken: jiraModel.SlackToken, SlackChannel: os.Getenv("SLACK_CHANNEL")})
		return resp.Status
	}

	log.WithFields(log.Fields{
		"status_code": resp.StatusCode,
		"status":      resp.Status,
	}).Warn("JIRA API returned non-success status")
	return resp.Status
}

// sanitizeTicketID sanitizes ticket ID to prevent path traversal
func sanitizeTicketID(ticketID string) string {
	// Remove any path traversal attempts
	ticketID = strings.ReplaceAll(ticketID, "..", "")
	ticketID = strings.ReplaceAll(ticketID, "/", "")
	ticketID = strings.ReplaceAll(ticketID, "\\", "")
	ticketID = strings.TrimSpace(ticketID)

	// Validate ticket ID format (alphanumeric and hyphens)
	if len(ticketID) == 0 || len(ticketID) > 50 {
		return ""
	}

	// Check for valid characters (alphanumeric, hyphens, underscores)
	for _, char := range ticketID {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_') {
			return ""
		}
	}

	return ticketID
}

// isBase64Encoded checks if a string is base64 encoded
func isBase64Encoded(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func SlackRespond(jiraModel models.JiraModel, slackData models.SlackData) {
	slack_app := slack.New(slackData.SlackToken)
	_, err := slack_app.AuthTest()
	HandleError(err, "Error while authenticating to Slack", false)

	_, _, err = slack_app.PostMessage(slackData.SlackChannel, slack.MsgOptionText("```"+"MORF Scan has been completed successfully"+"```", false))
	HandleError(err, "Error while sending message to Slack", false)
}
