package packetutil

import (
	"encoding/base64"
	"log"
	"net/url"
	"strings"
)

func (packetDetails *PacketDetails) FindBasicAuth() []string {
	potentialAuth := make([]string, 0)

	headers := packetDetails.extractHTTPHeaders()
	for i := 0; i < len(headers); i++ {
		value := headers[i]
		if strings.Contains(strings.ToLower(value), "authorization: basic") {
			basicAuth := strings.Split(value, "authorization: basic")
			if len(basicAuth) > 0 {
				decodedBase64, err := base64.StdEncoding.DecodeString(basicAuth[1])
				if err != nil {
					log.Println(err)
					continue
				}
				decodedBase64String := string(decodedBase64)
				if strings.Contains(decodedBase64String, ":") {
					potentialAuth = append(potentialAuth, decodedBase64String)
				}
			}
		}
	}
	return potentialAuth
}

func (packetDetails *PacketDetails) FindCookies() []string {
	valuesOfInterest := []string{"cookie"}
	potentialCookies := make([]string, 0)

	kvp := packetDetails.extractKVP()
	for i := 0; i < len(kvp); i++ {
		value := strings.ToLower(kvp[i])
		var password string

		for z := 0; z < len(valuesOfInterest); z++ {
			if strings.Contains(valuesOfInterest[z], value) {
				if len(kvp) > i+1 {
					password = kvp[i+1]
					potentialCookies = append(potentialCookies, password)
				}
			}
		}
	}
	return potentialCookies
}

func (packetDetails *PacketDetails) FindSessionID() []string {
	valuesOfInterest := []string{"id", "session"}
	potentialSessionIDs := make([]string, 0)

	kvp := packetDetails.extractKVP()
	for i := 0; i < len(kvp); i++ {
		value := kvp[i]
		var password string

		for z := 0; z < len(valuesOfInterest); z++ {
			if strings.Contains(valuesOfInterest[z], value) {
				if len(kvp) > i+1 {
					password = kvp[i+1]
					potentialSessionIDs = append(potentialSessionIDs, password)
				}
			}
		}
	}
	return potentialSessionIDs
}

func (packetDetails *PacketDetails) FindUsernames() []string {
	valuesOfInterest := []string{"user", "name"}
	potentialUsernames := make([]string, 0)

	kvp := packetDetails.extractKVP()
	for i := 0; i < len(kvp); i++ {
		value := kvp[i]
		var password string

		for z := 0; z < len(valuesOfInterest); z++ {
			if strings.Contains(valuesOfInterest[z], value) {
				if len(kvp) > i+1 {
					password = kvp[i+1]
					potentialUsernames = append(potentialUsernames, password)
				}
			}
		}
	}
	return potentialUsernames
}

func (packetDetails *PacketDetails) FindPasswords() []string {
	valuesOfInterest := []string{"pw", "pass"}
	potentialPasswords := make([]string, 0)

	kvp := packetDetails.extractKVP()
	for i := 0; i < len(kvp); i++ {
		value := kvp[i]
		var password string

		for z := 0; z < len(valuesOfInterest); z++ {
			if strings.Contains(valuesOfInterest[z], value) {
				if len(kvp) > i+1 {
					var err error

					passwordEncoded := kvp[i+1]
					password, err = url.PathUnescape(passwordEncoded)
					if err != nil {
						log.Println(err)
						continue
					}

					potentialPasswords = append(potentialPasswords, password)
				}
			}
		}
	}
	return potentialPasswords
}
