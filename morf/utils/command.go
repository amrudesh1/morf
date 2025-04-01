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
	"bytes"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

// ExecuteCommand executes a shell command and returns its output
func ExecuteCommand(command string, args ...string) (string, error) {
	log.Infof("Executing command: %s %s", command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Errorf("Command execution failed: %s\nStderr: %s", err, stderr.String())
		return "", err
	}

	return stdout.String(), nil
}

// SanitizeCommandOutput removes sensitive information from command output
func SanitizeCommandOutput(input string) string {
	// List of patterns to sanitize
	patterns := []struct {
		pattern string
		mask    string
	}{
		{`password=[\w\-\.]+`, "password=*****"},
		{`key=[\w\-\.]+`, "key=*****"},
		{`secret=[\w\-\.]+`, "secret=*****"},
		{`token=[\w\-\.]+`, "token=*****"},
		{`auth=[\w\-\.]+`, "auth=*****"},
	}

	result := input
	for _, p := range patterns {
		result = strings.ReplaceAll(result, p.pattern, p.mask)
	}

	return result
}

// ExecuteCommandWithSanitization executes a command and sanitizes its output
func ExecuteCommandWithSanitization(command string, args ...string) (string, error) {
	output, err := ExecuteCommand(command, args...)
	if err != nil {
		return "", err
	}
	return SanitizeCommandOutput(output), nil
}
