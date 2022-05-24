package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	packetUtils "passession-extractor/packetUtil"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/schollz/progressbar/v3"
)

var secretsArray []packetUtils.Secrets = make([]packetUtils.Secrets, 0)

func main() {
	var pcapFile string
	var outputFile string
	var moreDetails bool

	flag.StringVar(&pcapFile, "file", "", "-file=myCapture.pcap")
	flag.StringVar(&outputFile, "output", "secrets_dump.json", "-output=secrets.json")
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
	bar := progressbar.Default(int64(len(packetSource.Packets())))

	for packet := range packetSource.Packets() {
		packetDetails := packetUtils.NewPacketDetails(&packet)
		if packetDetails.GetApplicationLayer() == nil {
			continue //no application layer, we skip this packet
		}

		basicAuth := packetDetails.FindBasicAuth()
		cookies := packetDetails.FindCookies()
		usernames := packetDetails.FindUsernames()
		passwords := packetDetails.FindPasswords()
		if len(passwords) > 0 {
			fmt.Print()
		}
		if len(basicAuth) > 0 || len(cookies) > 0 || len(usernames) > 0 || len(passwords) > 0 {
			secrets := &packetUtils.Secrets{TimeStamp: packet.Metadata().Timestamp, MacFlow: packet.LinkLayer().LinkFlow().String(), IpFlow: packet.NetworkLayer().NetworkFlow().String(), PortFlow: packet.TransportLayer().TransportFlow().String(), BasicAuths: basicAuth, Cookies: cookies, Usernames: usernames, Passwords: passwords}

			duplicate := false
			for i := 0; i < len(secretsArray); i++ {
				if secretsArray[i].IsEqual(secrets) {
					duplicate = true
					break
				}
			}

			if !duplicate {
				secretsArray = append(secretsArray, *secrets)
			}
		}
		bar.Add(1)
	}

	file, err := os.Create(outputFile)
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
