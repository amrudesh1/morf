package apk

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"morf/models"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func StartMetaDataCollection(apkPath string) models.MetaDataModel {
	// Check if temp directory exist and If yes delete it and create a new one

	if _, err := os.Stat("temp"); err == nil {
		fmt.Println("Deleting the temp directory")
		os.RemoveAll("temp")
		fmt.Println("Creating a new temp directory")
		os.Mkdir("temp", 0777)
	} else {
		fmt.Println("Creating a new temp directory")
		os.Mkdir("temp", 0777)
	}

	if _, err := os.Stat("temp/input"); os.IsNotExist(err) {
		os.Mkdir("temp/input", 0755)
	}
	if _, err := os.Stat("temp/output"); os.IsNotExist(err) {
		os.Mkdir("temp/output", 0755)
	}

	os.Rename(apkPath, "temp/input/"+apkPath)
	apkPath = "temp/input/" + apkPath
	fmt.Println("Starting metadata collection for " + apkPath)

	metadata_success, metadata_error := exec.Command("java", "-cp", "tools/apkanalyzer.jar", "sk.styk.martin.bakalarka.execute.Main", "-analyze", "--in", "temp/input/", "--out", "temp/output").Output()
	fmt.Println(metadata_success)

	if metadata_error != nil {
		fmt.Println("Error while decompiling the APK file")
		log.Fatal(metadata_error)
		return models.MetaDataModel{}
	}

	if metadata_success != nil {
		fmt.Println("Metadata collection successful")
		file_path, file_name := filepath.Split(apkPath)
		fmt.Println(file_path)

		// Make file readable
		os.Chmod("temp/output/"+strings.Replace(file_name, ".apk", ".json", -1), 0777)
		return startFileParser("temp/output/" + strings.Replace(file_name, ".apk", ".json", -1))
	}

	return models.MetaDataModel{}
}

func startFileParser(s string) models.MetaDataModel {
	fmt.Println("Starting file parser:" + s)
	jsonFile, err := os.Open(s)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened " + s)
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var data models.MetaDataModel
	json.Unmarshal([]byte(byteValue), &data)
	return data

}
