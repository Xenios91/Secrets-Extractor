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
)

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

		passwords := packetDetails.FindPasswords()
		fmt.Println(passwords)
	}
}
