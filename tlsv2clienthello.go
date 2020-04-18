package main

import (
	//"errors"
	"fmt"
	"net"
)

type TlsV2ClientHello struct {
	Protocol     SslProtocol
	Ciphersuites []Ciphersuite
}

func (hello *TlsV2ClientHello) getHex() []byte {
	ciphersuites_hex := []byte{}
	for _, ciphersuite := range hello.Ciphersuites {
		ciphersuites_hex = append(ciphersuites_hex, ciphersuite.Value...)
	}
	packet_hex := []byte{}
	packet_hex = append(packet_hex, 0x80)              // bit 1: 2 byte header; bit 2: no security escapes, bits 3-8: high length bits
	packet_hex = append(packet_hex, get_len_and_hex(1, // record length
		[]byte{0x01},                         // message type (CLIENT HELLO)
		[]byte{0x00, 0x02},                   // version (0x0002)
		intToBytes(2, len(ciphersuites_hex)), // cipher specs list length
		[]byte{0x00, 0x00},                   // session ID length
		[]byte{0x00, 0x10},                   // challenge length
		ciphersuites_hex,
		getRandomBytes(16))...) // challenge data (16 bytes)
	return packet_hex
}

func (hello *TlsV2ClientHello) send(socket net.Conn) {
	fmt.Fprint(socket, string(hello.getHex()))
}
