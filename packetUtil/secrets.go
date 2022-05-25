package packetutil

import (
	"bytes"
	"encoding/json"
	"log"
	"reflect"
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
	Jwt        []string
}

func NewSecrets(timeStamp time.Time, MacFlow, ipFlow, portFlow *string, basicAuths, cookie, username, password, jwt []string) *Secrets {
	return &Secrets{timeStamp, *MacFlow, *ipFlow, *portFlow, basicAuths, cookie, username, password, jwt}
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

func (secrets *Secrets) IsEqual(secretToCompare *Secrets) bool {
	secretsTemp := *secrets
	secretsTemp.TimeStamp = time.Time{}
	secretToCompareTemp := *secretToCompare
	secretToCompareTemp.TimeStamp = time.Time{}

	isEqual := reflect.DeepEqual(secretsTemp, secretToCompareTemp)
	if !isEqual {
		secretsTempFields := reflect.ValueOf(secretsTemp)
		fields := make([]interface{}, secretsTempFields.NumField())

		for i := 0; i < secretsTempFields.NumField(); i++ {
			field := secretsTempFields.Field(i)
			fieldKind := field.Kind()
			if fieldKind == reflect.Slice {
				fields[i] = secretsTempFields.Field(i).Interface()
			}
		}

		secretsToCompareFields := reflect.ValueOf(secretToCompareTemp)
		fieldsToCompare := make([]interface{}, secretsToCompareFields.NumField())
		for i := 0; i < secretsToCompareFields.NumField(); i++ {
			field := secretsToCompareFields.Field(i)
			fieldKind := field.Kind()
			if fieldKind == reflect.Slice {
				fieldsToCompare[i] = secretsToCompareFields.Field(i).Interface()
			}
		}

		if len(fields) != len(fieldsToCompare) {
			return isEqual
		}

		for i := 0; i < len(fields); i++ {
			if !reflect.DeepEqual(fields[i], fieldsToCompare[i]) {
				return false
			}
		}
	}
	return isEqual
}
