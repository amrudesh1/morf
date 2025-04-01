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

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/amrudesh1/morf/models"
	"github.com/amrudesh1/morf/utils"

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

func StartSecScan(apkPath string) []models.SecretModel {
	counter := 0
	log.Println("Decompiling the APK file for sources")
	fmt.Println(apkPath)
	source_decompile, source_error := utils.ExecuteCommand("java", "-jar", "/app/tools/apktool.jar", "d", "-r", apkPath, "-o", utils.GetSourceDir())
	utils.HandleError(source_error, "Error while decompiling the APK file", true)

	if source_decompile != "" {
		log.Println("Decompiling the APK file for sources successful")
		counter++
	}

	//Decompile the resources of the APK file
	_, res_error := utils.ExecuteCommand("java", "-jar", "/app/tools/apktool.jar", "d", "-s", apkPath, "-o", utils.GetResDir())
	utils.HandleError(res_error, "Error while decompiling the APK file", true)

	if res_error == nil {
		log.Println("Decompiling the APK file for resources successful")
		counter++
	}

	if counter == 2 {
		log.Println("Decompiling the APK file successful")
		return SanitizeSecrets(StartScan())
	}

	return nil
}

func readPatternFile(patternFilePath string) []byte {
	yamlFile := utils.ReadFile(utils.GetAppFS(), patternFilePath)
	return yamlFile
}

func StartScan() []models.SecretModel {
	log.Info("Starting secret scan on the APK file")
	files := utils.ReadDir(utils.GetAppFS(), "/app/patterns")

	var wg sync.WaitGroup
	resultsChan := make(chan models.SecretModel, 100)

	// Create a mutex instance
	var mu sync.Mutex

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".yml") {
			wg.Add(1)
			go func(file os.FileInfo) {
				defer wg.Done()
				yamlFile := readPatternFile("/app/patterns/" + file.Name())
				var secretPatterns SecretPatterns
				err := yaml.Unmarshal(yamlFile, &secretPatterns)
				if err != nil {
					fmt.Printf("Error unmarshaling YAML file %s: %s\n", file.Name(), err)
					return
				}

				for _, pattern := range secretPatterns.Patterns {
					pat := pattern.Pattern.Regex
					log.Info("Searching for pattern: " + pat)
					result, err := utils.ExecuteCommand("rg", "-n", "-e", pat, "--multiline", utils.GetFilesDir())
					if err != nil {
						log.Debugf("No matches found for pattern: %s", pat)
						continue
					}

					stdout := strings.TrimSpace(string(result))
					if stdout != "" {
						log.Infof("Found matches for pattern: %s", pat)
						log.Infof("Matches: %s", stdout)
						lines := strings.Split(stdout, "\n")
						log.Debugf("Number of matches: %d", len(lines))
						for _, line := range lines {
							parts := strings.SplitN(line, ":", 3)
							if len(parts) < 3 {
								continue
							}

							fileName := parts[0]
							lineNumber, err := strconv.Atoi(parts[1])
							if err != nil {
								log.Errorf("Error converting line number: %s\n", err)
								continue
							}

							content := strings.TrimSpace(parts[2])
							secretString := extractSecret(content)
							secret := models.SecretModel{
								Type:             pattern.Pattern.Name,
								LineNo:           lineNumber,
								FileLocation:     fileName,
								SecretType:       pattern.Pattern.Name,
								SecretString:     secretString,
								SecretConfidence: pattern.Pattern.Confidence,
							}

							resultsChan <- secret
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
		mu.Lock()
		secretModel = append(secretModel, secret)
		mu.Unlock()
	}

	return secretModel
}

func extractSecret(content string) string {
	if strings.Contains(content, ">") && strings.Contains(content, "<") {
		begin := strings.Index(content, ">") + 1
		end := strings.LastIndex(content, "<")
		if begin < end && begin > 0 && end > 0 {
			return strings.TrimSpace(content[begin:end])
		}
	}

	if strings.Count(content, "\"") >= 2 {
		parts := strings.SplitN(content, "\"", 3)
		if len(parts) > 1 {
			return parts[1]
		}
	}

	lastColon := strings.LastIndex(content, ":")
	if lastColon != -1 {
		return strings.TrimSpace(content[lastColon+1:])
	}

	return content
}

func SanitizeSecrets(scanner_data []models.SecretModel) []models.SecretModel {
	var sanitizedSecrets []models.SecretModel
	uniqueSecrets := make(map[string]models.SecretModel)

	for _, secret := range scanner_data {
		if _, exists := uniqueSecrets[secret.SecretString]; !exists {
			uniqueSecrets[secret.SecretString] = secret
			sanitizedSecrets = append(sanitizedSecrets, secret)
		}
	}

	for _, secret := range sanitizedSecrets {
		fmt.Printf("Type: %s\n", secret.Type)
		fmt.Printf("Secret: %s\n", secret.SecretString)
		fmt.Printf("File Name %s\n", secret.FileLocation)
		fmt.Println()
		fmt.Println("-----------------------------------")
	}
	return sanitizedSecrets
}
