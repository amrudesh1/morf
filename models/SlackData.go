package models

type SlackData struct {
	SlackToken   string `json:"slackToken" binding:"required"`
	SlackChannel string `json:"slackChannel" binding:"required"`
	TimeStamp    string `json:"timeStamp"`
}
