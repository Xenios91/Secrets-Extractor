package packetutil

import (
	"fmt"
	"strings"
)

func (packetDetails *PacketDetails) FindPasswords() []string {
	valuesOfInterest := []string{"pw", "pass"}
	potentialPasswords := make([]string, 0)

	headers := packetDetails.extractHTTPHeaders()
	fmt.Println(headers)
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
