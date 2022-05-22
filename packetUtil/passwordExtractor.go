package packetutil

import (
	"encoding/base64"
	"log"
	"strings"
)

func (packetDetails *PacketDetails) FindPasswords() []string {
	valuesOfInterest := []string{"pw", "pass"}
	potentialPasswords := make([]string, 0)

	headers := packetDetails.extractHTTPHeaders()
	for i := 0; i < len(headers); i++ {
		value := headers[i]
		if strings.Contains(strings.ToLower(value), "authorization: basic") {
			basicAuth := strings.Split(value, "authorization: basic")
			if len(basicAuth > 0) {
				decodedBase64, err := base64.StdEncoding.DecodeString(basicAuth[1])
				if err != nil {
					log.Println(err)
					continue
				}
				decodedBase64String := string(decodedBase64)
				if strings.Contains(decodedBase64String, ":") {
					potentialPasswords = append(potentialPasswords, strings.Split(decodedBase64String, ":")[1])
				}
			}
		}
	}

	kvp := packetDetails.extractKVP()
	for i := 0; i < len(kvp); i++ {
		value := kvp[i]
		var password string

		for z := 0; z < len(valuesOfInterest); z++ {
			if strings.Contains(valuesOfInterest[z], value) {
				if len(kvp) > i+1 {
					password = kvp[i+1]
					potentialPasswords = append(potentialPasswords, password)
				}
			}
		}
	}
	return potentialPasswords
}
