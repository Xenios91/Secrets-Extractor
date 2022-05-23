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
	return potentialAuth
}

func (packetDetails *PacketDetails) FindCookies() []string {
	valuesOfInterest := []string{"cookie"}
	potentialCookies := make([]string, 0)

	headers := packetDetails.extractHTTPHeaders()
	for i := 0; i < len(headers); i++ {
		value := strings.ToLower(headers[i])
		var cookie string

		for z := 0; z < len(valuesOfInterest); z++ {
			if strings.Contains(value, valuesOfInterest[z]) {
				cookie = headers[i]
				potentialCookies = append(potentialCookies, cookie)
			}
		}
	}
	return potentialCookies
}

func (packetDetails *PacketDetails) FindUsernames() []string {
	valuesOfInterest := []string{"user", "name"}
	potentialUsernames := make([]string, 0)

	kvp := packetDetails.extractKVP()
	for i := 0; i < len(kvp); i++ {
		value := kvp[i]
		var username string

		for z := 0; z < len(valuesOfInterest); z++ {
			if strings.Contains(valuesOfInterest[z], value) {
				if len(kvp) > i+1 {
					username = kvp[i+1]
					potentialUsernames = append(potentialUsernames, username)
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
