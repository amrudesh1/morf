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
	log "github.com/sirupsen/logrus"
)

// HandleError handles errors with optional message and fatal flag
func HandleError(err error, message string, fatal bool) {
	if err != nil {
		if message != "" {
			log.Error(message + ": " + err.Error())
		} else {
			log.Error(err)
		}
		if fatal {
			log.Fatal("Fatal error occurred")
		}
	}
}

// LogError logs an error with an optional message
func LogError(err error, message string) {
	if err != nil {
		if message != "" {
			log.Error(message + ": " + err.Error())
		} else {
			log.Error(err)
		}
	}
}

// LogWarning logs a warning message
func LogWarning(message string) {
	log.Warn(message)
}

// LogInfo logs an info message
func LogInfo(message string) {
	log.Info(message)
}

// LogDebug logs a debug message
func LogDebug(message string) {
	log.Debug(message)
}
