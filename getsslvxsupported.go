package main

import (
	"fmt"
	"net"
)

func getSslV2Supported(ip string, port int) ([]TlsV2ServerResponse, error) {
	sslV2Ciphersuites := getAllSslV2Ciphersuites()
	protoSslV2 := SslProtocolFromString("0200")
	clientHello := TlsV2ClientHello{Protocol: protoSslV2}
	successfullServerResponses := []TlsV2ServerResponse{}
	for _, ciphersuite := range sslV2Ciphersuites {
		socket, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
		if err != nil {
			return nil, ErrorCannotConnect
		}
		clientHello.Ciphersuites = []Ciphersuite{ciphersuite}
		clientHello.send(socket)

		serverHello := TlsV2ServerResponse{}
		_, err = serverHello.read(socket)
		if err == nil {
			successfullServerResponses = append(successfullServerResponses, serverHello)
		}
		socket.Close()
	}
	return successfullServerResponses, nil
}

func getSslV3Supported(ip string, port int) ([]TlsV3ServerResponse, error) {
	sslV3Ciphersuites := getAllSslV3Ciphersuites()
	v3Protos := [...]string{"0300", "0301", "0302", "0303"}
	successfullServerResponses := []TlsV3ServerResponse{}

	for _, stringProto := range v3Protos {
		protoSslV2 := SslProtocolFromString(stringProto)
		clientHello := TlsV3ClientHello{Protocol: protoSslV2}
		for _, ciphersuite := range sslV3Ciphersuites {
			socket, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
			if err != nil {
				return nil, ErrorCannotConnect
			}
			clientHello.Ciphersuites = []Ciphersuite{ciphersuite}
			clientHello.send(socket)

			serverHello := TlsV3ServerResponse{}
			_, err = serverHello.read(socket)
			if err == nil {
				successfullServerResponses = append(successfullServerResponses, serverHello)
			}
			socket.Close()
		}
	}
	return successfullServerResponses, nil
}
