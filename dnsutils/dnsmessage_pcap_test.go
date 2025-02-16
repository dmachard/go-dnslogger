package dnsutils

import (
	"testing"

	"github.com/dmachard/go-netutils"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestToPacketLayer_DoT_Translation(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dnscollector.dev.", dns.TypeAAAA)
	dnsquestion, _ := dnsmsg.Pack()

	dm.NetworkInfo.Family = netutils.ProtoIPv4
	dm.NetworkInfo.Protocol = ProtoDoT
	dm.NetworkInfo.QueryIP = "127.0.0.8"
	dm.NetworkInfo.QueryPort = "12345"
	dm.NetworkInfo.ResponseIP = "127.0.0.10"
	dm.NetworkInfo.ResponsePort = "853"
	dm.DNS.Type = DNSQuery

	dm.DNS.Payload = dnsquestion
	dm.DNS.Length = len(dnsquestion)

	overwriteDstPort := false
	pkt, err := dm.ToPacketLayer(overwriteDstPort)
	assert.NoError(t, err)

	// check source and dest
	udpLayer, ok := pkt[1].(*layers.UDP)
	assert.True(t, ok, "Expected TCP layer")
	assert.Equal(t, 853, int(udpLayer.DstPort), "Expected destination port 853 for DoT")
	assert.NotZero(t, udpLayer.SrcPort, "Expected non-zero source port")
}

func TestToPacketLayer_DoT_OverwriteDestinationPort(t *testing.T) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dnscollector.dev.", dns.TypeAAAA)
	dnsquestion, _ := dnsmsg.Pack()

	dm.NetworkInfo.Family = netutils.ProtoIPv4
	dm.NetworkInfo.Protocol = ProtoDoT
	dm.NetworkInfo.QueryIP = "127.0.0.8"
	dm.NetworkInfo.QueryPort = "12345"
	dm.NetworkInfo.ResponseIP = "127.0.0.10"
	dm.NetworkInfo.ResponsePort = "853"
	dm.DNS.Type = DNSQuery

	dm.DNS.Payload = dnsquestion
	dm.DNS.Length = len(dnsquestion)

	overwriteDstPort := true
	pkt, err := dm.ToPacketLayer(overwriteDstPort)
	assert.NoError(t, err)

	// check source and dest
	udpLayer, ok := pkt[1].(*layers.UDP)
	assert.True(t, ok, "Expected TCP layer")
	assert.Equal(t, 53, int(udpLayer.DstPort), "Expected destination port 53 for DoT")
	assert.NotZero(t, udpLayer.SrcPort, "Expected non-zero source port")
}

// Tests for PCAP serialization
func BenchmarkDnsMessage_ToPacketLayer(b *testing.B) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()

	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dnscollector.dev.", dns.TypeAAAA)
	dnsquestion, _ := dnsmsg.Pack()

	dm.NetworkInfo.Family = netutils.ProtoIPv4
	dm.NetworkInfo.Protocol = netutils.ProtoUDP
	dm.DNS.Payload = dnsquestion
	dm.DNS.Length = len(dnsquestion)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dm.ToPacketLayer(false)
		if err != nil {
			b.Fatalf("could not encode to pcap: %v\n", err)
		}
	}
}
