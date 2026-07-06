package utils

import (
	"io/fs"

	alf "github.com/spf13/afero"
	vip "github.com/spf13/viper"
)

const tmpDir = "/tmp/morf"

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
	exists, _ := alf.DirExists(fs, vip.GetString("backup_path"))
	return exists
}

func CreateBackUpDir(fs alf.Fs) {
	fs.Mkdir(vip.GetString("backup_path"), 0755)
}

func GetAppFS() alf.Fs {
	return alf.NewOsFs()
}

func WriteToFile(fs alf.Fs, path string, data string) error {
	return alf.WriteFile(fs, path, []byte(data), 0644)
}

func ReadFile(fs alf.Fs, path string) ([]byte, error) {
	return alf.ReadFile(fs, path)
}

func ReadDir(fs alf.Fs, path string) []fs.FileInfo {
	files, _ := alf.ReadDir(fs, path)
	return files
}
