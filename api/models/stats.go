package models

type AgentStats struct {
	Total   int `json:"Total"`
	Safe    int `json:"Safe"`
	Blocked int `json:"Blocked"`
}