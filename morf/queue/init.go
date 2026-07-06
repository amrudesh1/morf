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

package queue

import (
	"os"

	log "github.com/sirupsen/logrus"
)

var (
	// GlobalJobQueue is the global job queue instance
	GlobalJobQueue *JobQueue
)

// InitQueue initializes the global job queue
func InitQueue() error {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379" // Default
	}

	log.WithFields(log.Fields{
		"redis_url": redisURL,
	}).Info("Initializing Redis job queue")

	queue, err := NewJobQueue(redisURL)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Error("Failed to initialize job queue")
		return err
	}

	GlobalJobQueue = queue
	log.Info("Job queue initialized successfully")
	return nil
}

// GetQueue returns the global job queue
func GetQueue() *JobQueue {
	return GlobalJobQueue
}
