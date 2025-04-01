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
<<<<<<< HEAD:morf/models/slack.go
=======
*/ /*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
>>>>>>> main:main.go
*/

<<<<<<< HEAD:morf/models/slack.go
package models
=======
import "github.com/amrudesh1/morf/cmd"
>>>>>>> main:main.go

// SlackData represents data received from Slack command
type SlackData struct {
	SlackToken   string `json:"slackToken" binding:"required"`
	SlackChannel string `json:"slackChannel" binding:"required"`
	TimeStamp    string `json:"timeStamp"`
}
