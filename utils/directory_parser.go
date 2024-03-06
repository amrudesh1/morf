package utils

import (
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	alf "github.com/spf13/afero"
)

const tmpDir = "/tmp/morf"
const filesDir = tmpDir + "/output/apk/"
const sourceDir = tmpDir + "/output/apk/source"
const resDir = tmpDir + "/output/apk/appres"

func CreateMorfDirintmp(fs alf.Fs) {
	fs.Mkdir("/tmp/morf", 0755)
}

func CreateInputOutputDir(fs alf.Fs) {
	fs.Mkdir(tmpDir+"/input", 0755)
	fs.Mkdir(tmpDir+"/output", 0755)
}

func CheckifmorftmpDirExists(fs alf.Fs) bool {
	exists, _ := alf.DirExists(fs, tmpDir)
	return exists
}

func CopyApktoInputDir(appFS alf.Fs, apkPath string) string {
	// Check if APK path is absolute or relative if its absolute then Lets only get the file name from the path and use it as the destination file name
	var fileName string
	if apkPath[0] == '/' {
		fileName = filepath.Base(apkPath)
	} else {
		fileName = apkPath
	}

	fmt.Println("APK Path:", apkPath)
	destinationFilePath := tmpDir + "/input/" + fileName

	srcFile, err := appFS.Open(apkPath)
	HandleError(err, "Error while opening the APK file", true)

	defer srcFile.Close()
	destFile, err := appFS.Create(destinationFilePath)
	HandleError(err, "Error while creating the destination file", true)

	defer destFile.Close()

	fmt.Println("Moving APK to input directory:", tmpDir+"/input/"+apkPath)

	_, err = io.Copy(destFile, srcFile)
	HandleError(err, "Error while copying the APK file", true)

	return destinationFilePath
}

func GetTmpDir() string {
	return tmpDir
}

func GetInputDir() string {
	return tmpDir + "/input/"
}

func GetOutputDir() string {
	return tmpDir + "/output/"
}

func GetApkPath(apkPath string) string {
	return tmpDir + "/input/" + apkPath
}

func DeleteTmpDir(fs alf.Fs) {
	fs.RemoveAll(tmpDir)
}

func CheckBackUpDirExists(fs alf.Fs) bool {
	exists, _ := alf.DirExists(fs, "/backup")
	return exists
}

func CreateBackUpDir(fs alf.Fs) {
	fs.Mkdir("/backup", 0755)
}

func GetAppFS() alf.Fs {
	return alf.NewOsFs()
}

func WriteToFile(fs alf.Fs, path string, data string) {
	_ = alf.WriteFile(fs, path, []byte(data), 0644)
}

func GetSourceDir() string {
	return sourceDir
}

func GetResDir() string {
	return resDir
}

func GetFilesDir() string {
	return filesDir
}

func ReadFile(fs alf.Fs, path string) []byte {
	data, _ := alf.ReadFile(fs, path)

	return data
}

func ReadDir(fs alf.Fs, path string) []fs.FileInfo {
	files, _ := alf.ReadDir(fs, path)
	return files
}
