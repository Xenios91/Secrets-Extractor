package packetutil

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"
)

func (packetDetails *PacketDetails) findBasicAuth() []string {
	potentialAuth := make([]string, 0)

	headers, _ := packetDetails.extractHttpComponents()
	for i := 0; i < len(headers); i++ {
		value := headers[i]
		if strings.Contains(value, "Authorization: Basic") {
			basicAuth := strings.Split(value, "Authorization: Basic")
			if len(basicAuth) > 0 {
				encodedCreds := strings.TrimSpace(basicAuth[1])
				decodedBase64, err := base64.StdEncoding.DecodeString(encodedCreds)
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

	if len(potentialAuth) > 0 {
		fmt.Print()
	}
	return potentialAuth
}

func isHTML(value *string) bool {
	return strings.Contains(*value, "<div") || strings.Contains(*value, "<html")
}

func (packetDetails *PacketDetails) findCookies() []string {
	valuesOfInterest := []string{"cookie"}
	potentialCookies := make([]string, 0)

	headers, _ := packetDetails.extractHttpComponents()
	for i := 0; i < len(headers); i++ {
		value := strings.ToLower(headers[i])
		var cookie string

		for z := 0; z < len(valuesOfInterest); z++ {
			if strings.Contains(value, valuesOfInterest[z]) {
				cookie = headers[i]
				if !isHTML(&cookie) {
					potentialCookies = append(potentialCookies, cookie)
				}
			}
		}
	}
	return potentialCookies
}

func (packetDetails *PacketDetails) FindCredentials() (map[string][]string, bool) {
	secrets := make(map[string][]string)
	usernameValuesOfInterest := []string{"user", "name"}
	passwordValuesOfInterest := []string{"pass", "pw"}
	secrets["usernames"] = make([]string, 0)
	secrets["passwords"] = make([]string, 0)
	secrets["cookies"] = packetDetails.findCookies()
	secrets["basicauth"] = packetDetails.findBasicAuth()

	_, kvp := packetDetails.extractHttpComponents()

	i := 0
search_start:
	for i < len(kvp) {
		kvpValue := kvp[i]

		for z := 0; z < len(usernameValuesOfInterest); z++ {
			if strings.Contains(kvpValue, usernameValuesOfInterest[z]) && !isHTML(&kvpValue) {
				username := kvp[i]
				secrets["usernames"] = append(secrets["usernames"], username)
				i++
				goto search_start
			}
		}

		for z := 0; z < len(passwordValuesOfInterest); z++ {
			if strings.Contains(kvpValue, passwordValuesOfInterest[z]) {
				password := kvp[i]
				secrets["passwords"] = append(secrets["passwords"], password)
				i++
				goto search_start
			}
		}

		i++
	}

	found := len(secrets["usernames"]) > 0 || len(secrets["passwords"]) > 0 || len(secrets["cookies"]) > 0 || len(secrets["basicauth"]) > 0
	return secrets, found
}
