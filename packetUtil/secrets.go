package packetutil

import (
	"bytes"
	"encoding/json"
	"log"
	"time"
)

type Secrets struct {
	TimeStamp  time.Time
	MacFlow    string
	IpFlow     string
	PortFlow   string
	BasicAuths []string
	Cookies    []string
	Usernames  []string
	Passwords  []string
}

func NewSecrets(timeStamp time.Time, MacFlow, ipFlow, portFlow *string, basicAuths, cookie, username, password []string) *Secrets {
	return &Secrets{timeStamp, *MacFlow, *ipFlow, *portFlow, basicAuths, cookie, username, password}
}

func (secrets *Secrets) ToJson() *string {
	buffer := bytes.NewBuffer([]byte{})
	jsonEncoder := json.NewEncoder(buffer)
	jsonEncoder.SetEscapeHTML(false)
	err := jsonEncoder.Encode(secrets)
	if err != nil {
		log.Println(err)
		return nil
	}

	jsonString := buffer.String()
	return &jsonString
}
