package models

type JiraModel struct {
	FileUrl    string `json:"fileUrl"`
	SlackToken string `json:"slackToken"`
	Ticket_id  string `json:"ticket_id"`
	JiraToken  string `json:"jiraToken"`
}
