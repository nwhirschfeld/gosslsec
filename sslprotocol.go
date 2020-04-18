package main

import (
	"encoding/hex"
	"fmt"
)

type SslProtocol struct {
	Value []byte
}

func (protocol *SslProtocol) GetName() string {
	switch string(protocol.Value) {
	case string([]byte{0x02, 0x00}):
		return "SSLv2.0"
	case string([]byte{0x03, 0x00}):
		return "SSLv3.0"
	case string([]byte{0x03, 0x01}):
		return "TLSv1.0"
	case string([]byte{0x03, 0x02}):
		return "TLSv1.1"
	case string([]byte{0x03, 0x03}):
		return "TLSv1.2"
	}
	return fmt.Sprintf("UNKNOWN_PROTOCOL_%x", protocol.Value)
}

func (protocol *SslProtocol) String() string {
	return fmt.Sprintf("%s (%x)", protocol.GetName(), protocol.Value)
}

func SslProtocolFromString(val string) SslProtocol {
	proto, _ := hex.DecodeString(val)
	return SslProtocol{proto}
}
