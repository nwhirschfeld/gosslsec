package main

import (
	"bytes"
	//"errors"
	"fmt"
	"net"
)

type TlsV3ClientHello struct {
	Protocol     SslProtocol
	Ciphersuites []Ciphersuite
}

func (hello *TlsV3ClientHello) getHex() []byte {
	ciphersuites_hex := []byte{}
	for _, ciphersuite := range hello.Ciphersuites {
		ciphersuites_hex = append(ciphersuites_hex, ciphersuite.Value...)
	}
	packet_hex := []byte{}
	packet_hex = append(packet_hex, 0x16)                    // content type: handshake (22)
	packet_hex = append(packet_hex, hello.Protocol.Value...) // protocol
	packet_hex = append(packet_hex, get_len_and_hex(2,       // handshake len
		[]byte{0x01}, //client hello
		get_len_and_hex(3, // hello len
			hello.Protocol.Value,
			[]byte{0x4f, 0xde, 0xd1, 0xb9}, // time
			getRandomBytes(28),             // random
			[]byte{0x00},                   // session id length
			get_len_and_hex(2, ciphersuites_hex, []byte{0x00, 0xff}), // cipersuites
			get_len_and_hex(1, []byte{0x00}),                         // compression methods
			ifAppend((bytes.Compare(hello.Protocol.Value, []byte{0x03, 0x03}) == 0), // append extentions just for tlsv1.3
				get_len_and_hex(2,
					[]byte{0x00, 0x0D}, // signature algos
					get_len_and_hex(2, get_len_and_hex(2, // extentiondata
						[]byte{0x06, 0x01, 0x06, 0x03}, // sha512 + rsa/ecdsa
						[]byte{0x05, 0x01, 0x05, 0x03}, // sha384 + rsa/ecdsa
						[]byte{0x04, 0x01, 0x04, 0x03}, // sha256 + rsa/ecdsa
						[]byte{0x03, 0x01, 0x03, 0x03}, // sha224 + rsa/ecdsa
						[]byte{0x02, 0x01, 0x02, 0x03} /* sha1 + rsa/ecdsa */))))))...,
	)
	return packet_hex
}

func (hello *TlsV3ClientHello) send(socket net.Conn) {
	fmt.Fprint(socket, string(hello.getHex()))
}
