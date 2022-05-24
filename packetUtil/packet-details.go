package packetutil

import (
	"strings"

	"github.com/google/gopacket"
)

type PacketDetails struct {
	packetContents gopacket.Packet
}

func NewPacketDetails(packet *gopacket.Packet) *PacketDetails {
	return &PacketDetails{packetContents: *packet}
}

func (packet *PacketDetails) GetApplicationLayer() gopacket.ApplicationLayer {
	return packet.packetContents.ApplicationLayer()
}

func (packetDetails *PacketDetails) extractHttpComponents() ([]string, []string) {
	var headerPairs []string
	var bodyPairs []string

	applicationLayer := packetDetails.GetApplicationLayer()
	payloadAsString := string(applicationLayer.Payload())
	headerTerminator := "\r\n\r\n"
	endOfHeaderElement := strings.Index(payloadAsString, headerTerminator)
	if endOfHeaderElement != -1 {
		headerAsString := payloadAsString[:endOfHeaderElement+len(headerTerminator)]
		headerPairs = strings.Split(headerAsString, "\r\n")
		bodyAsString := payloadAsString[endOfHeaderElement+len(headerTerminator):]
		bodyPairs = strings.Split(bodyAsString, "&")
	}
	return headerPairs, bodyPairs
}
