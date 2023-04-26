package apk

// Import Ripgrep library for searching for secrets in the code

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"morf/models"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type SecretPatterns struct {
	Patterns []struct {
		Pattern struct {
			Name       string `yaml:"name"`
			Regex      string `yaml:"regex"`
			Confidence string `yaml:"confidence"`
		} `yaml:"pattern"`
	} `yaml:"patterns"`
}

type PatternList struct {
	Patterns []struct {
		Pattern struct {
			Name string
		}
	}
}

var secretPatterns SecretPatterns
var secretModel []models.SecretModel
var dummyCoutner int = 0

func CheckAPK(apkPath string) {
	PacakgeData := ExtractPackageData("scan.apk")
	log.Info(PacakgeData)
}

func StartSecScan(apkPath string) []models.SecretModel {
	//Decompile the sources of the APK file
	counter := 0

	log.Println("Decompiling the APK file for sources")
	source_decompile, source_error := exec.Command("java", "-jar", "tools/apktool.jar", "d", "-r", apkPath, "-o", "temp/output/apk/source").Output()

	if source_error != nil {
		log.Println("Error while decompiling the APK file")
		log.Fatal(source_error)
	}

	if source_decompile != nil {
		log.Println("Decompiling the APK file for sources successful")
		counter++
	}

	//Decompile the resources of the APK file

	log.Println("Decompiling the APK file for resources")
	res_decompile, res_error := exec.Command("java", "-jar", "tools/apktool.jar", "d", "-s", apkPath, "-o", "temp/output/apk/appreso").Output()

	if res_error != nil {
		log.Println("Error while decompiling the resources of the APK file")
		log.Fatal(res_error)
	}

	if res_decompile != nil {
		log.Println("Decompiling the APK file for resources successful")
		counter++
	}
	files_path := "temp/output/apk/"
	if counter == 2 {
		log.Println("Decompiling the APK file successful")
		return StartScan(files_path)
	}
	return nil
}

func handleError(err error, msg string, exitCode1 bool) {
	if err != nil {
		if exitCode1 {
			if exitError, ok := err.(*exec.ExitError); ok {
				if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.ExitStatus() == 1 {
					fmt.Println(msg, "Pattern not found.")
					return
				}
			}
		}
		fmt.Println(msg, err)
	}
}

func readPatternFile(patternFilePath string) ([]byte, error) {
	patternFile, err := os.OpenFile(patternFilePath, os.O_RDONLY, 0666)
	defer patternFile.Close()
	handleError(err, "Error opening pattern file:", true)

	yamlFile, err := ioutil.ReadAll(patternFile)
	handleError(err, "Error reading pattern file:", true)

	return yamlFile, err
}

func StartScan(apkPath string) []models.SecretModel {

	files, err := ioutil.ReadDir("patterns")
	handleError(err, "Error reading directory:", true)

	for _, file := range files {
		fmt.Println("File:", file.Name())

		yamlFile, err := readPatternFile("patterns/" + file.Name())
		if err != nil {
			continue
		}

		err = yaml.Unmarshal(yamlFile, &secretPatterns)
		if err != nil {
			fmt.Println(file.Name())
			fmt.Println(err)
			continue
		}

		for _, pattern := range secretPatterns.Patterns {

			pat := pattern.Pattern.Regex
			cmd := exec.Command("rg", "-n", "-e", fmt.Sprintf("\"%s\"", pat), "--multiline", apkPath)

			// Sleep for 1 second to avoid rate limiting
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			handleError(err, "Error running ripgrep:", true)

			if stdout.Len() > 0 {

				// Split Stdout into lines and iterate over them
				lines := strings.Split(stdout.String(), "\n")
				for _, line := range lines {

					parts := strings.SplitN(line, ":", 3)
					if len(parts) != 3 {
						fmt.Printf("Invalid RipGrep output: %s\n", stdout.String())
						continue
					}

					fileName := parts[0]
					lineNumber, err := strconv.Atoi(parts[1])
					content := parts[2]

					contentParts := strings.SplitN(strings.TrimSpace(content), " ", 2)
					typeName := contentParts[0]
					patternFound := ""
					if len(contentParts) > 1 {
						patternFound = contentParts[1]
					}

					if err == nil {
						secretModel = append(secretModel, models.SecretModel{
							Type:         pattern.Pattern.Name,
							LineNo:       lineNumber,
							FileLocation: fileName,
							SecretType:   typeName,
							SecretString: patternFound,
						})

						log.Info(secretModel)
						log.Info(len(secretModel))
					}
				}
			}
		}
	}
	return secretModel
}
