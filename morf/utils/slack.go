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
	"encoding/json"
	"fmt"
	"io"
	"morf/models"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
)

// isAllowedSlackHost reports whether host is exactly an approved Slack domain or
// a true dotted subdomain of one. This is stricter than a bare HasSuffix check,
// which "evilslack.com" would wrongly pass.
func isAllowedSlackHost(host string) bool {
	h := strings.ToLower(host)
	return h == "slack.com" || strings.HasSuffix(h, ".slack.com") ||
		h == "slack-edge.com" || strings.HasSuffix(h, ".slack-edge.com") ||
		h == "slack-files.com" || strings.HasSuffix(h, ".slack-files.com")
}

// validateSlackFileURL parses fileURL, enforces that the host is an approved
// Slack domain (exact/dotted-suffix match), and resolves the host to reject any
// private/loopback/link-local destination so a leaked bearer token cannot be
// used to reach internal hosts (SSRF / DNS-rebinding defence).
func validateSlackFileURL(fileURL string) error {
	parsedURL, err := url.Parse(fileURL)
	if err != nil {
		return fmt.Errorf("invalid file URL: %w", err)
	}
	host := parsedURL.Hostname()
	if !isAllowedSlackHost(host) {
		return fmt.Errorf("file URL must be from an approved slack.com domain")
	}
	// Resolve and reject internal addresses.
	if ip := net.ParseIP(host); ip != nil {
		if isInternalSlackIP(ip) {
			return fmt.Errorf("file URL resolves to a disallowed IP (SSRF protection)")
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve file URL host: %w", err)
	}
	for _, ip := range ips {
		if isInternalSlackIP(ip) {
			return fmt.Errorf("file URL resolves to a disallowed IP (SSRF protection)")
		}
	}
	return nil
}

// isInternalSlackIP reports whether ip is private, loopback or link-local.
func isInternalSlackIP(ip net.IP) bool {
	return ip == nil || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// MaxAPKDownloadSize is the maximum allowed APK download size in bytes (500 MB).
// Override this package variable before calling download functions if a different
// limit is needed.
var MaxAPKDownloadSize = int64(500 << 20)

// apkDownloadTimeout is the per-request HTTP timeout applied when downloading APK
// files from Slack.
const apkDownloadTimeout = 30 * time.Second

// slackPostTimeout is the per-request HTTP timeout applied when posting messages
// back to Slack.
const slackPostTimeout = 30 * time.Second

// maxSlackPostWorkers caps the number of concurrent Slack PostMessage calls made
// by RespondSecretsToSlack.
const maxSlackPostWorkers = 4

// limitedWriter wraps an io.Writer and returns an error if the cumulative number
// of bytes written would exceed limit, defending against oversized downloads.
type limitedWriter struct {
	w     io.Writer
	n     int64
	limit int64
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.n >= lw.limit {
		return 0, fmt.Errorf("download exceeds maximum allowed size of %d bytes", lw.limit)
	}
	remaining := lw.limit - lw.n
	if int64(len(p)) > remaining {
		// Write only up to the limit, then signal that the file is too large.
		n, err := lw.w.Write(p[:remaining])
		lw.n += int64(n)
		if err != nil {
			return n, err
		}
		return n, fmt.Errorf("download exceeds maximum allowed size of %d bytes", lw.limit)
	}
	n, err := lw.w.Write(p)
	lw.n += int64(n)
	return n, err
}

// newDownloadClient returns an *http.Client configured with a hard timeout for
// APK file downloads.
func newDownloadClient() *http.Client {
	return &http.Client{Timeout: apkDownloadTimeout}
}

// GetDownloadURLFromSlack extracts the download URL from Slack command data
// Security improvements:
// - Validates file type before download
// - Validates URL is from slack.com domain
// - Adds size limit on downloads (500MB)
// - Adds timeout on HTTP downloads (30 seconds)
func GetDownloadUrlFromSlack(slackData models.SlackData, ctx *gin.Context) string {
	requestID := ctx.GetString("request_id")

	log.WithFields(log.Fields{
		"request_id": requestID,
		"channel":    slackData.SlackChannel,
		"timestamp":  slackData.TimeStamp,
	}).Info("Processing Slack file download request")

	slack_app := slack.New(slackData.SlackToken, slack.OptionHTTPClient(newDownloadClient()))

	_, err := slack_app.AuthTest()
	if err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"error":      err.Error(),
		}).Error("Slack authentication failed")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Slack authentication failed"})
		return ""
	}

	history, err := slack_app.GetConversationHistory(&slack.GetConversationHistoryParameters{
		ChannelID: slackData.SlackChannel,
	})

	if err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"error":      err.Error(),
		}).Error("Failed to get Slack conversation history")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return ""
	}

	file_url := ""
	file_name := ""

	for _, value := range history.Messages {
		if value.Timestamp == slackData.TimeStamp {
			for _, file := range value.Files {
				file_url = file.URLPrivateDownload
				file_name = file.Name
			}
		}
	}

	if file_url == "" || file_name == "" {
		log.WithFields(log.Fields{
			"request_id": requestID,
		}).Error("File not found in Slack message")
		ctx.JSON(http.StatusNotFound, gin.H{"error": "File not found in Slack message"})
		return ""
	}

	// Validate URL is from an approved slack.com domain and does not resolve to
	// an internal address (SSRF / DNS-rebinding protection).
	if err := validateSlackFileURL(file_url); err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"error":      err.Error(),
		}).Error("File URL failed SSRF validation")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return ""
	}

	// Validate file type before download (must be APK)
	if !strings.HasSuffix(strings.ToLower(file_name), ".apk") {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"file_name":  file_name,
		}).Error("File is not an APK")
		ctx.JSON(http.StatusBadRequest, gin.H{
			"status":  http.StatusBadRequest,
			"message": "Only APK files are allowed",
		})
		return ""
	}

	// Create file with unique name to prevent collisions
	uniqueFileName := generateUniqueFileName(file_name)

	log.WithFields(log.Fields{
		"request_id":  requestID,
		"file_url":    maskURLForLogging(file_url), // Mask URL in logs
		"file_name":   file_name,
		"unique_name": uniqueFileName,
	}).Info("Downloading file from Slack")

	file, err := os.Create(uniqueFileName)
	if err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"error":      err.Error(),
		}).Error("Failed to create file")
		return ""
	}

	defer file.Close()

	// Download file with a 30-second timeout (via newDownloadClient) and a
	// 500 MB size cap enforced by limitedWriter.
	lw := &limitedWriter{w: file, limit: MaxAPKDownloadSize}
	if err := slack_app.GetFile(file_url, lw); err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"error":      err.Error(),
		}).Error("Failed to download file from Slack")
		os.Remove(uniqueFileName) // Clean up on failure
		return ""
	}

	log.WithFields(log.Fields{
		"request_id": requestID,
		"file_name":  uniqueFileName,
	}).Info("File downloaded successfully from Slack")

	return uniqueFileName
}

// generateUniqueFileName generates a unique filename to prevent collisions
func generateUniqueFileName(originalName string) string {
	timestamp := time.Now().UnixNano()
	ext := filepath.Ext(originalName)
	name := strings.TrimSuffix(originalName, ext)
	return fmt.Sprintf("%s_%d%s", name, timestamp, ext)
}

// maskURLForLogging masks sensitive parts of a URL for logging
func maskURLForLogging(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return "****"
	}
	// Mask query parameters and path
	return parsed.Scheme + "://" + parsed.Host + "/****"
}

// DownloadFileUsingSlack downloads a file from a URL provided in Slack
// Security improvements:
// - Validates URL is from slack.com domain (SSRF protection)
// - Validates file type before download
// - Adds size limit on downloads (500MB)
// - Adds timeout on HTTP downloads (30 seconds)
func DownloadFileUsingSlack(jiraModel models.JiraModel, ctx *gin.Context) string {
	requestID := ctx.GetString("request_id")

	log.WithFields(log.Fields{
		"request_id": requestID,
		"file_url":   maskURLForLogging(jiraModel.FileUrl),
	}).Info("Processing Slack file download request")

	slack_app := slack.New(jiraModel.SlackToken, slack.OptionHTTPClient(newDownloadClient()))
	_, err := slack_app.AuthTest()

	if err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"error":      err.Error(),
		}).Error("Slack authentication failed")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Slack authentication failed"})
		return ""
	}

	// Validate URL is from an approved slack.com domain and does not resolve to
	// an internal address (SSRF / DNS-rebinding protection).
	if err := validateSlackFileURL(jiraModel.FileUrl); err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"error":      err.Error(),
		}).Error("File URL failed SSRF validation")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return ""
	}

	// Split URL and get the last part of the URL
	urlStr := jiraModel.FileUrl
	url_split := strings.Split(urlStr, "/")
	file_name := url_split[len(url_split)-1]

	// Validate file type before download (must be APK)
	if !strings.HasSuffix(strings.ToLower(file_name), ".apk") {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"file_name":  file_name,
		}).Error("File is not an APK")
		ctx.JSON(http.StatusBadRequest, gin.H{
			"status":  http.StatusBadRequest,
			"message": "Only APK files are allowed",
		})
		return ""
	}

	// Create file with unique name
	uniqueFileName := generateUniqueFileName(file_name)

	file, err := os.Create(uniqueFileName)
	if err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"error":      err.Error(),
		}).Error("Failed to create file")
		return ""
	}

	defer file.Close()

	// Download with a 30-second timeout (via newDownloadClient) and a 500 MB
	// size cap enforced by limitedWriter.
	lw := &limitedWriter{w: file, limit: MaxAPKDownloadSize}
	if err := slack_app.GetFile(jiraModel.FileUrl, lw); err != nil {
		log.WithFields(log.Fields{
			"request_id": requestID,
			"error":      err.Error(),
		}).Error("Failed to download file from Slack")
		os.Remove(uniqueFileName)
		return ""
	}

	log.WithFields(log.Fields{
		"request_id": requestID,
		"file_name":  uniqueFileName,
	}).Info("File downloaded successfully from Slack")

	ctx.JSON(http.StatusOK, gin.H{
		"status":  http.StatusOK,
		"message": "Downloading of APK successful",
	})

	return uniqueFileName
}

// RespondSecretsToSlack sends scan results back to Slack.
// Chunks are posted concurrently (up to maxSlackPostWorkers in flight) using an
// HTTP client with a per-request timeout. When more than one chunk is produced,
// each is prefixed with its index so out-of-order delivery is identifiable.
// All errors are aggregated; a single chunk failure does not abort the others.
func RespondSecretsToSlack(slackData models.SlackData, ctx *gin.Context, data string) {
	chunks := parseSlackData(data)
	total := len(chunks)

	postClient := &http.Client{Timeout: slackPostTimeout}
	slack_app := slack.New(slackData.SlackToken, slack.OptionHTTPClient(postClient))

	var (
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
		sem  = make(chan struct{}, maxSlackPostWorkers)
	)

	for i, message := range chunks {
		wg.Add(1)
		sem <- struct{}{} // acquire a worker slot
		go func(idx int, msg string) {
			defer wg.Done()
			defer func() { <-sem }() // release the slot

			// Prefix each chunk with its sequence number when there are multiple
			// chunks so the reader can reconstruct the intended order even if
			// Slack delivers replies out of order.
			text := msg
			if total > 1 {
				text = fmt.Sprintf("[%d/%d]\n%s", idx+1, total, msg)
			}

			_, _, err := slack_app.PostMessage(
				slackData.SlackChannel,
				slack.MsgOptionText("```"+text+"```", false),
				slack.MsgOptionTS(slackData.TimeStamp),
			)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				log.WithField("chunk", idx+1).Error("Error sending message chunk to Slack:", err)
			}
		}(i, message)
	}

	wg.Wait()

	if len(errs) > 0 {
		log.Errorf("RespondSecretsToSlack: %d of %d chunk(s) failed to post", len(errs), total)
	}
}

func parseSlackData(data string) []string {
	var secrets models.Secrets

	apk_data := json.Unmarshal([]byte(data), &secrets)
	if apk_data != nil {
		log.Error(apk_data)
	}

	if len(secrets.SecretModel) > 0 {
		return parseSecretModel(secrets)
	}
	return []string{"** No secrets found **"}
}

func parseSecretModel(secrets models.Secrets) []string {
	var messages []string
	var currentMessage string

	currentMessage = "APK Name: " + secrets.FileName + "\n" +
		"App Version: " + secrets.PackageDataModel.VersionName + "\n" +
		"Package Name: " + secrets.PackageDataModel.PackageName + "\n" +
		"SHA1: " + secrets.APKHash + "\n" +
		"\n" +
		"Secrets in APK: \n" +
		"----------------\n" +
		"" + strconv.Itoa(len(secrets.SecretModel)) + " secrets found\n" +
		"----------------\n"

	for _, value := range []models.SecretModel(secrets.SecretModel) {
		secretEntry := "Secret Type: " + value.Type + "\n" +
			"Secret Value: " + value.SecretString + "\n" +
			"Secret Type: " + value.SecretType + "\n" +
			"Line No: " + strconv.Itoa(value.LineNo) + "\n" +
			"File Location: " + value.FileLocation + "\n" +
			"----------------\n"

		if len(currentMessage)+len(secretEntry) > 4000 { // Slack has a 4000-character limit per message
			messages = append(messages, currentMessage)
			currentMessage = ""
		}

		currentMessage += secretEntry
	}

	if currentMessage != "" {
		messages = append(messages, currentMessage)
	}

	return messages
}
