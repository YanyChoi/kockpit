package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func main() {

	handle2, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle2.Close()

	packets := make(chan gopacket.Packet)

	go routine(handle2, packets)

	// Write packets to a file
	file, _ := os.Create("output.pcap")
	f := pcapgo.NewWriter(io.NewOffsetWriter(file, 0))
	f.WriteFileHeader(1600, handle2.LinkType())
	for pkt := range packets {
		f.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
		fmt.Printf(pkt.String())
	}
	file.Close()

}

func routine(handle *pcap.Handle, packets chan gopacket.Packet) {
	for packet := range gopacket.NewPacketSource(handle, handle.LinkType()).Packets() {
		packets <- packet
	}
}
