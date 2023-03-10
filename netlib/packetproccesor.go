package netlib

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// DefragPacket is a struct that holds DNS data
type DnsPacket struct {
	// DNS payload
	Payload []byte
	// IP layer
	IpLayer gopacket.Flow
	// Transport layer
	TransportLayer gopacket.Flow
	// Timestamp
	Timestamp time.Time
}

func UdpProcessor(udpInput chan gopacket.Packet, dnsOutput chan DnsPacket, portFilter int) {
	for packet := range udpInput {
		p := packet.TransportLayer().(*layers.UDP)
		if int(p.SrcPort) != portFilter && int(p.DstPort) != portFilter {
			continue
		}

		dnsOutput <- DnsPacket{
			Payload:        p.Payload,
			IpLayer:        packet.NetworkLayer().NetworkFlow(),
			TransportLayer: p.TransportFlow(),
			Timestamp:      packet.Metadata().Timestamp,
		}
	}
}

func TcpAssembler(tcpInput chan gopacket.Packet, dnsOutput chan DnsPacket, portFilter int) {
	streamFactory := &DnsStreamFactory{Reassembled: dnsOutput}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	for packet := range tcpInput {
		p := packet.TransportLayer().(*layers.TCP)
		if int(p.SrcPort) != portFilter && int(p.DstPort) != portFilter {
			continue
		}
		assembler.AssembleWithTimestamp(
			packet.NetworkLayer().NetworkFlow(),
			packet.TransportLayer().(*layers.TCP),
			packet.Metadata().Timestamp,
		)
	}
	assembler.FlushAll()
}

func IpDefragger(ipInput chan gopacket.Packet, udpOutput chan gopacket.Packet, tcpOutput chan gopacket.Packet) {
	defragger := NewIPDefragmenter()
	for fragment := range ipInput {
		reassembled, err := defragger.DefragIP(fragment)
		if err != nil {
			fmt.Println(err)
			break
		} else if reassembled == nil {
			continue
		} else {
			if reassembled.TransportLayer() != nil && reassembled.TransportLayer().LayerType() == layers.LayerTypeUDP {
				udpOutput <- reassembled
			}
			if reassembled.TransportLayer() != nil && reassembled.TransportLayer().LayerType() == layers.LayerTypeTCP {
				tcpOutput <- reassembled
			}
		}
	}
}
