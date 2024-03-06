package models

type JiraModel struct {
	JiraHost   string `json:"hostUrl"`
	FileUrl    string `json:"fileUrl"`
	SlackToken string `json:"slackToken"`
	Ticket_id  string `json:"ticket_id"`
	JiraToken  string `json:"jiraToken"`
}
