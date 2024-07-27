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

func StartSecScan(apkPath string) []models.SecretModel {
	counter := 0
	log.Println("Decompiling the APK file for sources")
	fmt.Println(apkPath)
	source_decompile, source_error := exec.Command("java", "-jar", "tools/apktool.jar", "d", "-r", apkPath, "-o", utils.GetSourceDir()).Output()
	utils.HandleError(source_error, "Error while decompiling the APK file", true)

	if source_decompile != nil {
		log.Println("Decompiling the APK file for sources successful")
		counter++
	}

	//Decompile the resources of the APK file
	res_decompile, res_error := utils.ExecuteCommand("java", []string{"-jar", "tools/apktool.jar", "d", "-s", apkPath, "-o", utils.GetResDir()}, false, true)
	utils.HandleError(res_error, "Error while decompiling the APK file", true)

	if res_decompile != nil {
		log.Println("Decompiling the APK file for resources successful")
		counter++
	}

	if counter == 2 {
		log.Println("Decompiling the APK file successful")
		return utils.SanitizeSecrets(StartScan(utils.GetSourceDir()))
	}

	return nil
}

func readPatternFile(patternFilePath string) []byte {

	yamlFile := utils.ReadFile(utils.GetAppFS(), patternFilePath)
	return yamlFile
}

func StartScan(apkPath string) []models.SecretModel {
	log.Info("Scanning for secrets in the code")
	files := utils.ReadDir(utils.GetAppFS(), "patterns")

	var wg sync.WaitGroup
	resultsChan := make(chan models.SecretModel, 100)

	// Create a mutex instance
	var mu sync.Mutex

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".yml") {
			wg.Add(1)
			go func(file os.FileInfo) {
				defer wg.Done()
				yamlFile := readPatternFile("patterns/" + file.Name())
				// Make sure file name is ending with .yml or .yaml
				err := error(nil)
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
