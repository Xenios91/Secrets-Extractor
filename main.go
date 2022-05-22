package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	var pcapFile string

	flag.StringVar(&pcapFile, "file", "", "-file=myCapture.pcap")

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
		fmt.Println(packet)
	}
}
