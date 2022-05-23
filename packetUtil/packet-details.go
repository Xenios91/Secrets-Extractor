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

func (packetDetails *PacketDetails) extractHTTPHeaders() []string {
	applicationLayer := packetDetails.GetApplicationLayer()
	payloadAsString := string(applicationLayer.Payload())
	headersTemp := strings.Split(payloadAsString, "\r\n")
	headers := make([]string, 0)

	for i := 0; i < len(headersTemp); i++ {
		if len(headersTemp[i]) > 0 {
			headers = append(headers, headersTemp[i])
		}
	}
	return headers
}

func (packetDetails *PacketDetails) extractKVP() []string {
	applicationLayer := packetDetails.GetApplicationLayer()
	payloadAsString := string(applicationLayer.Payload())
	headerTerminator := "\r\n\r\n"
	endOfHeaderElement := strings.Index(payloadAsString, headerTerminator)
	payloadAsString = payloadAsString[endOfHeaderElement+len(headerTerminator):]

	kvp := strings.Split(payloadAsString, "=")
	return kvp
}
