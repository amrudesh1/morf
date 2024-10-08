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
*/package apk

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/amrudesh1/morf/models"
	"github.com/amrudesh1/morf/utils"

	log "github.com/sirupsen/logrus"
	alf "github.com/spf13/afero"
)

func StartMetaDataCollection(apkPath string) models.MetaDataModel {
	// Check if temp directory exist and If yes delete it and create a new one

	fs := alf.NewOsFs()

	if utils.CheckifmorftmpDirExists(fs) {
		log.Debug("Deleting the temp directory")
		utils.DeleteTmpDir(fs)
		log.Debug("Creating a new temp directory")
		utils.CreateMorfDirintmp(fs)
	} else {
		log.Debug("Creating a new temp directory")
		utils.CreateMorfDirintmp(fs)
	}

	// Create input and output directory
	if _, err := os.Stat(utils.GetInputDir()); os.IsNotExist(err) {
		utils.CreateInputOutputDir(fs)
	}

	// Move APK to input directory
	apkPath = utils.CopyApktoInputDir(fs, apkPath)

	log.Info("Starting metadata collection for " + apkPath)

	metadata_success, metadata_error := exec.Command("java", "-cp", "tools/apkanalyzer.jar", "sk.styk.martin.bakalarka.execute.Main", "-analyze", "--in", utils.GetInputDir(), "--out", utils.GetOutputDir()).Output()

	if metadata_error != nil {
		log.Error("Error while decompiling the APK file")
		log.Fatal(metadata_error)
		return models.MetaDataModel{}
	}

	if metadata_success != nil {
		log.Debug("Metadata collection successful")
		file_path, file_name := filepath.Split(apkPath)
		log.Debug(file_path)

		// Make file readable
		os.Chmod(utils.GetOutputDir()+strings.Replace(file_name, ".apk", ".json", -1), 0777)
		return startFileParser(utils.GetOutputDir() + strings.Replace(file_name, ".apk", ".json", -1))
	}

	return models.MetaDataModel{}
}

func startFileParser(s string) models.MetaDataModel {
	log.Debug("Starting file parser:" + s)
	jsonFile, err := os.Open(s)
	if err != nil {
		log.Error(err)
	}
	log.Debug("Successfully Opened " + s)
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var data models.MetaDataModel
	json.Unmarshal([]byte(byteValue), &data)
	return data

}
