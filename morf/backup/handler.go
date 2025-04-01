package backup

import (
	"encoding/json"
	"morf/models"
	"morf/utils"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

// BackupHandler handles backup operations
type BackupHandler struct {
	fs afero.Fs
}

// NewBackupHandler creates a new instance of BackupHandler
func NewBackupHandler(fs afero.Fs) *BackupHandler {
	return &BackupHandler{
		fs: fs,
	}
}

// HandleBackup performs backup operations for the given secret and data
func (h *BackupHandler) HandleBackup(secret models.Secrets, secretData []byte) error {
	// Check if backup directory exists
	exists := utils.CheckBackUpDirExists(h.fs)
	if !exists {
		utils.CreateBackUpDir(h.fs)
	}

	// Create report with JSON data
	jsonData, err := json.MarshalIndent(secret, "", " ")
	if err != nil {
		log.Error("Failed to marshal secret data:", err)
		return err
	}

	// Create report
	utils.CreateReport(h.fs, secret, jsonData, secretData, secret.FileName)
	return nil
}
