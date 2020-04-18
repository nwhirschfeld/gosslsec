package main

import (
	"encoding/hex"
	"fmt"
)

type Ciphersuite struct {
	Value []byte
}

func (ciphersuite *Ciphersuite) GetName() string {
	return CipherNameMap[string(ciphersuite.Value)]
}

func (ciphersuite *Ciphersuite) String() string {
	return fmt.Sprintf("%s (%x)", ciphersuite.GetName(), ciphersuite.Value)
}

func CiphersuiteFromString(val string) Ciphersuite {
	csuite, _ := hex.DecodeString(val)
	return Ciphersuite{csuite}
}

func getAllSslV2Ciphersuites() []Ciphersuite {
	sslV2CiphersuitesStrings := []string{"000000", "010080", "020080", "030080", "040080", "050080", "060040", "060140", "0700c0", "0701c0", "080080", "ff0800", "ff0810", "0000ff"}
	sslV2Ciphersuites := []Ciphersuite{}
	for _, ciphersuiteString := range sslV2CiphersuitesStrings {
		sslV2Ciphersuites = append(sslV2Ciphersuites, CiphersuiteFromString(ciphersuiteString))
	}
	return sslV2Ciphersuites
}

func getAllSslV3Ciphersuites() []Ciphersuite {
	sslV3Ciphersuites := []Ciphersuite{}
	for i := 0; i <= 255; i++ {
		sslV3Ciphersuites = append(sslV3Ciphersuites,
			Ciphersuite{Value: []byte{0x00, byte(i)}})
		sslV3Ciphersuites = append(sslV3Ciphersuites,
			Ciphersuite{Value: []byte{0xc0, byte(i)}})
	}
	return sslV3Ciphersuites
}
