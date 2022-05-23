package packetutil

import (
	"encoding/json"
	"log"
)

type Secrets struct {
	BasicAuths []string
	Cookies    []string
	Usernames  []string
	Passwords  []string
}

func NewSecrets(basicAuths, cookie, username, password []string) *Secrets {
	return &Secrets{basicAuths, cookie, username, password}
}

func (secrets *Secrets) ToJson() *string {
	jsonBytes, err := json.Marshal(secrets)
	if err != nil {
		log.Println(err)
		return nil
	}

	jsonString := string(jsonBytes)
	return &jsonString
}
