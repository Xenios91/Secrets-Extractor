package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	packetUtils "passession-extractor/packetUtil"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	secretsArray []packetUtils.Secrets = make([]packetUtils.Secrets, 0)
	wg           sync.WaitGroup
	mutexLock    = &sync.Mutex{}
)

func getDeviceList() []pcap.Interface {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Devices Found:")
	for deviceNum, device := range devices {
		fmt.Printf("\n%d. %s\nDescription: %s\n", deviceNum, device.Name, device.Description)

		var addresses strings.Builder
		addresses.WriteString("Addresses: [")
		addressCount := len(device.Addresses)
		if addressCount == 0 {
			addresses.WriteString("None")
		}

		for addressNum, address := range device.Addresses {
			addresses.WriteString(address.IP.String())
			if addressNum != addressCount-1 {
				addresses.WriteString(", ")
			}
		}
		addresses.WriteString("]")
		fmt.Println(addresses.String())
	}

	return devices
}

func getDeviceSelection() pcap.Interface {
	var input string
	var shouldContinue string
	var device pcap.Interface
	devices := getDeviceList()

	for shouldContinue != "y" {
		fmt.Println("\nPlease select the device number you wish to capture on:")
		fmt.Scanln(&input)

		inputToInt, err := strconv.Atoi(input)
		if err != nil {
			continue
		}

		device = devices[inputToInt]

		validContinue := false
		for !validContinue {
			fmt.Printf("You selected device: [%s], would you like to continue? y/n\n", device.Name)
			fmt.Scanln(&shouldContinue)
			if strings.ToLower(shouldContinue) == "y" || strings.ToLower(shouldContinue) == "n" {
				validContinue = true
			}
		}

	}

	return device
}

func getLiveCaptureHandle() *pcap.Handle {
	device := getDeviceSelection()
	var snapshot_len int32 = 1024
	var promiscuous bool = true
	var timeout time.Duration = 30 * time.Second

	handle, err := pcap.OpenLive(device.Name, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatalln(err)
	}

	return handle
}

func processPacket(packet gopacket.Packet) {
	defer wg.Done()
	packetDetails := packetUtils.NewPacketDetails(&packet)
	if packetDetails.GetApplicationLayer() == nil {
		return
	}

	secrets, found := packetDetails.FindCredentials()

	if found {
		secrets := &packetUtils.Secrets{TimeStamp: packet.Metadata().Timestamp, MacFlow: packet.LinkLayer().LinkFlow().String(), IpFlow: packet.NetworkLayer().NetworkFlow().String(), PortFlow: packet.TransportLayer().TransportFlow().String(), BasicAuths: secrets["basicauth"], Cookies: secrets["cookies"], Usernames: secrets["usernames"], Passwords: secrets["passwords"], Jwt: secrets["jwt"]}

		duplicate := false
		for i := 0; i < len(secretsArray); i++ {
			if secretsArray[i].IsEqual(secrets) {
				duplicate = true
				break
			}
		}

		if !duplicate {
			mutexLock.Lock()
			defer mutexLock.Unlock()
			secretsArray = append(secretsArray, *secrets)
		}
	}
}

func createSecretsFile(outputFile string) {
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

func main() {
	var pcapFile string
	var outputFile string
	var handle *pcap.Handle

	flag.StringVar(&pcapFile, "file", "", "-file=myCapture.pcap")
	flag.StringVar(&outputFile, "output", "secrets_dump.json", "-output=secrets.json")
	flag.Parse()

	if len(pcapFile) == 0 {
		handle = getLiveCaptureHandle()
		log.Println("Starting packet capture... Use CTRL + C to end capture")
	} else {
		if _, err := os.Stat(pcapFile); errors.Is(err, os.ErrNotExist) {
			flag.PrintDefaults()
			log.Fatalf("file [%s] not found!\n", pcapFile)
		}
		var err error
		handle, err = pcap.OpenOffline(pcapFile)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Checking packets from file: [%s]\n", pcapFile)
	}
	defer handle.Close()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	terminateCapture := false

	//go routine to check for os signals to gracefully end capture
	go func() {
		<-sigs
		fmt.Println("Ending capture... please wait... if this takes more than a few minutes please use CTR + Z to terminate")
		terminateCapture = true
	}()

	//process 1000 packets at max in parrallel
	packetChan := make(chan gopacket.Packet, 1000)

	//service to grab packets
	go func(packetChan chan gopacket.Packet) {
		for {
			packet := <-packetChan
			go processPacket(packet)
		}
	}(packetChan)

	counter := 1
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		if terminateCapture {
			break
		}

		wg.Add(1)
		packetChan <- packet
		counter++
	}

	wg.Wait()

	log.Printf("Packets checked: [%d]\n", counter)
	createSecretsFile(outputFile)
	log.Printf("Extracted values stored in: [%s]\n", outputFile)
}
