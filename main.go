package main

import (
	"errors"
	"flag"
	"log"
	"os"
	packetUtils "passession-extractor/packetUtil"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var secretsArray []packetUtils.Secrets = make([]packetUtils.Secrets, 0)

func main() {
	var pcapFile string
	var moreDetails bool

	flag.StringVar(&pcapFile, "file", "", "-file=myCapture.pcap")
	flag.BoolVar(&moreDetails, "details", false, "-details=false")
	flag.Parse()

	if moreDetails {
		log.Println("I'm not very good with names, go away...\nanywho, contact me if you have additional questions, hope you enjoy.")
	}

	if _, err := os.Stat(pcapFile); errors.Is(err, os.ErrNotExist) {
		flag.PrintDefaults()
		log.Fatalf("file [%s] not found!\n", pcapFile)
	}

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetDetails := packetUtils.NewPacketDetails(&packet)
		if packetDetails.Packet.ApplicationLayer() == nil {
			continue //no application layer, we skip this packet
		}

		basicAuth := packetDetails.FindBasicAuth()
		sessionIDs := packetDetails.FindSessionID()
		cookies := packetDetails.FindCookies()
		usernames := packetDetails.FindUsernames()
		passwords := packetDetails.FindPasswords()
		if len(basicAuth) > 0 || len(sessionIDs) > 0 || len(cookies) > 0 || len(usernames) > 0 || len(passwords) > 0 {
			secrets := &packetUtils.Secrets{BasicAuths: basicAuth, SessionIDs: sessionIDs, Cookies: cookies, Usernames: usernames, Passwords: passwords}
			secretsArray = append(secretsArray, *secrets)
		}
	}

	file, err := os.Create("secrets_dump.json")
	if err != nil {
		log.Fatalln(err)
	}

	for i := 0; i < len(secretsArray); i++ {
		_, err = file.WriteString(*secretsArray[i].ToJson())
		if err != nil {
			log.Println(err)
		}
	}
}
