package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
)

type TlsV2ServerResponse struct {
	Ciphersuites []Ciphersuite
	Certificate  x509.Certificate
}

func (shello *TlsV2ServerResponse) read(socket net.Conn) (*TlsV2ServerResponse, error) {
	data := getBytesFromSocket(socket, 2)
	if len(data) < 2 {
		return nil, ErrorNotSSLV2ServerHello
	}
	if bytes.Compare(data, []byte{0x80, 0x00}) == 0 {
		return nil, ErrorNotSSLV2ServerHello
	}
	serverMessageLength := bytesToInt(data) & 0x7FFF
	if serverMessageLength < 11 {
		return nil, ErrorNotSSLV2ServerHello
	}
	serverMessageHex := getBytesFromSocket(socket, serverMessageLength)
	if serverMessageHex[0] != 0x04 {
		return nil, ErrorNotSSLV2ServerHello
	}
	certificateLength := bytesToInt(serverMessageHex[5:7])
	ciphersuiteLength := bytesToInt(serverMessageHex[7:9])
	connectionIdLength := bytesToInt(serverMessageHex[9:11])

	if serverMessageLength != 11+certificateLength+ciphersuiteLength+connectionIdLength {
		return nil, ErrorNotSSLV2ServerHello
	}

	if ciphersuiteLength%3 != 0 {
		return nil, ErrorNotSSLV2ServerHello
	}
	cnt := 11
	certificateData, cnt := nextBytes(serverMessageHex, cnt, certificateLength)
	cert, _ := x509.ParseCertificate(certificateData)
	shello.Certificate = *cert
	ciphersuiteData, cnt := nextBytes(serverMessageHex, cnt, ciphersuiteLength)
	for i := 0; i < len(ciphersuiteData); i += 3 {
		shello.Ciphersuites = append(shello.Ciphersuites, Ciphersuite{ciphersuiteData[i : i+3]})
	}
	_, cnt = nextBytes(serverMessageHex, cnt, connectionIdLength)
	return shello, nil
}

func (shello *TlsV2ServerResponse) String() string {
	lines := []string{}
	lines = append(lines, "Ciphersuites:")
	for _, ciphersuite := range shello.Ciphersuites {
		lines = append(lines, fmt.Sprintf("  - %s", ciphersuite.String()))
	}
	scanner := bufio.NewScanner(strings.NewReader(X509CertificateString(shello.Certificate)))
	for scanner.Scan() {
		lines = append(lines, fmt.Sprintf("  %s", scanner.Text()))
	}
	return strings.Join(lines, "\n")
}
