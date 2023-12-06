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
package apk

// Import Ripgrep library for searching for secrets in the code

import (
	"fmt"
	"io/ioutil"
	"morf/models"
	"morf/utils"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

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

	res_decompile, res_error := utils.ExecuteCommand("java", []string{"-jar", "tools/apktool.jar", "d", "-s", apkPath, "-o", "temp/output/apk/appreso"}, false, true)

	if res_error != nil {
		log.Println("Error while decompiling the resources of the APK file")
		log.Error(res_error)
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

func readPatternFile(patternFilePath string) ([]byte, error) {
	patternFile, err := os.OpenFile(patternFilePath, os.O_RDONLY, 0666)
	defer patternFile.Close()
	utils.HandleError(err, "Error opening pattern file:", true)

	yamlFile, err := ioutil.ReadAll(patternFile)
	utils.HandleError(err, "Error reading pattern file:", true)

	return yamlFile, err
}

func StartScan(apkPath string) []models.SecretModel {
	files, err := ioutil.ReadDir("patterns")
	utils.HandleError(err, "Error reading directory:", true)

	var wg sync.WaitGroup
	resultsChan := make(chan models.SecretModel, 100)

	// Create a mutex instance
	var mu sync.Mutex

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".yml") {
			wg.Add(1)
			go func(file os.FileInfo) {
				defer wg.Done()
				yamlFile, err := readPatternFile("patterns/" + file.Name())
				// Make sure file name is ending with .yml or .yaml

				if err != nil {
					fmt.Println(err)
				}

				mu.Lock()
				err = yaml.Unmarshal(yamlFile, &secretPatterns)
				mu.Unlock()

				if err != nil {
					fmt.Printf("Error unmarshaling YAML file %s:\n%s\n", file.Name(), err)
					fmt.Printf("YAML content:\n%s\n", string(yamlFile))
					return
				}

				if err != nil {
					fmt.Println(file.Name())
					fmt.Println(err)
					return
				}

				for _, pattern := range secretPatterns.Patterns {
					pat := pattern.Pattern.Regex
					fmt.Println(pat)
					stdout, err := utils.ExecuteCommand("rg", []string{"-n", "-e", fmt.Sprintf("\"%s\"", pat), "--multiline", apkPath}, true, false)

					utils.HandleError(err, "Error running ripgrep:", true)
					if stdout != nil {
						if stdout.Len() > 0 {
							// Split Stdout into lines and iterate over them
							lines := strings.Split(stdout.String(), "\n")
							for _, line := range lines {
								parts := strings.SplitN(line, ":", 3)
								if len(parts) != 3 {
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

								// Split Secret String between double quotes
								if err == nil {
									secret := models.SecretModel{
										Type:         pattern.Pattern.Name,
										LineNo:       lineNumber,
										FileLocation: fileName,
										SecretType:   typeName,
										SecretString: strings.Split(patternFound, "\"")[1],
									}

									resultsChan <- secret
								}
							}
						}
					}
				}
			}(file)
		}
	}

	wg.Wait()
	close(resultsChan)

	var secretModel []models.SecretModel

	for secret := range resultsChan {
		// Lock the critical section
		mu.Lock()
		secretModel = append(secretModel, secret)
		mu.Unlock()
	}

	return secretModel
}
