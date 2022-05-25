package packetutil

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"
)

func findJwt(headers []string) []string {
	potentialJwt := make([]string, 0)

	for i := 0; i < len(headers); i++ {
		value := headers[i]
		if strings.Contains(value, "Authorization: Bearer") {
			jwt := strings.Split(value, "Authorization: Bearer")
			if len(jwt) > 0 {
				encodedJwt := strings.TrimSpace(jwt[1])
				decodedBase64, err := base64.StdEncoding.DecodeString(encodedJwt)
				if err != nil {
					log.Println(err)
					continue
				}
				decodedBase64String := string(decodedBase64)
				if strings.Contains(decodedBase64String, ":") {
					potentialJwt = append(potentialJwt, decodedBase64String)
				}
			}
		}
	}
	return potentialJwt
}

func findBasicAuth(headers []string) []string {
	potentialAuth := make([]string, 0)

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

func findCookies(headers []string) []string {
	valuesOfInterest := []string{"cookie"}
	potentialCookies := make([]string, 0)

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

func findUsernames(kvp []string) []string {
	usernameValuesOfInterest := []string{"user", "name"}
	usernames := make([]string, 0)

	for i := 0; i < len(kvp); i++ {
		kvpValue := kvp[i]

		for z := 0; z < len(usernameValuesOfInterest); z++ {
			if strings.Contains(kvpValue, usernameValuesOfInterest[z]) && !isHTML(&kvpValue) {
				username := kvp[i]
				usernames = append(usernames, username)
			}
		}
	}
	return usernames
}

func findPasswords(kvp []string) []string {
	passwordValuesOfInterest := []string{"pass", "pw"}
	passwords := make([]string, 0)

	for i := 0; i < len(kvp); i++ {
		kvpValue := kvp[i]

		for z := 0; z < len(passwordValuesOfInterest); z++ {
			if strings.Contains(kvpValue, passwordValuesOfInterest[z]) && !isHTML(&kvpValue) {
				password := kvp[i]
				passwords = append(passwords, password)
			}
		}
	}
	return passwords
}

func (packetDetails *PacketDetails) FindCredentials() (map[string][]string, bool) {
	secrets := make(map[string][]string)
	headers, kvp := packetDetails.extractHttpComponents()

	secrets["usernames"] = findUsernames(kvp)
	secrets["passwords"] = findPasswords(kvp)
	secrets["cookies"] = findCookies(headers)
	secrets["basicauth"] = findBasicAuth(headers)
	secrets["jwt"] = findJwt(headers)

	found := len(secrets["usernames"]) > 0 || len(secrets["passwords"]) > 0 || len(secrets["cookies"]) > 0 || len(secrets["basicauth"]) > 0 || len(secrets["jwt"]) > 0
	return secrets, found
}
