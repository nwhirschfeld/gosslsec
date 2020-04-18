package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
)

var nameofcc map[string]string
var numberofcc map[string]string

func main() {

	fmt.Println("Starting ssl-cipher-enum, go version")

	var host string
	flag.StringVar(&host, "host", "127.0.0.1", "host to scan")
	portNum := flag.Int("port", 443, "port to scan")
	flag.Parse()

	ip := host
	port := *portNum

	sslV2Ciphersuites, err := getSslV2Supported(ip, port)
	if err == ErrorCannotConnect {
		fmt.Printf("[!] Could not connect to port.")
		os.Exit(1)
	}
	sslV3Ciphersuites, err := getSslV3Supported(ip, port)
	if err == ErrorCannotConnect {
		fmt.Printf("[!] Could not connect to port.")
		os.Exit(1)
	}

	// SSL supported?
	if len(sslV2Ciphersuites)+len(sslV3Ciphersuites) == 0 {
		fmt.Printf("[I] no ssl supported on %s:%d\n", ip, port)
	}

	// supported Ciphers
	for _, cipher := range sslV2Ciphersuites {
		if len(cipher.Ciphersuites) > 0 {
			fmt.Printf("[I] %s:%d supports %s %s\n", ip, port, "SSLv2.0", cipher.Ciphersuites[0].GetName())
		}
	}
	for _, cipher := range sslV3Ciphersuites {
		fmt.Printf("[I] %s:%d supports %s %s\n", ip, port, cipher.Protocol.GetName(), cipher.ServerHello.Ciphersuite.GetName())
	}

	// get one certificate
	var certificate x509.Certificate
	if len(sslV2Ciphersuites) > 0 {
		certificate = sslV2Ciphersuites[0].Certificate
	} else {
		certificate = sslV3Ciphersuites[0].Certificate[0]
	}
	fmt.Printf("[I] %s:%d certificate signature algorithm: %s\n", ip, port, certificate.SignatureAlgorithm)
	fmt.Printf("[I] %s:%d certificate signature length: %d\n", ip, port, len(certificate.Signature))
	fmt.Printf("[I] %s:%d certificate public key algorithm: %s\n", ip, port, certificate.PublicKeyAlgorithm)
	fmt.Printf("[I] %s:%d certificate issuer: %s\n", ip, port, certificate.Issuer)
	fmt.Printf("[I] %s:%d certificate subject: %s\n", ip, port, certificate.Subject)
	fmt.Printf("[I] %s:%d certificate valid from: %s\n", ip, port, certificate.NotBefore)
	fmt.Printf("[I] %s:%d certificate valid until: %s\n", ip, port, certificate.NotAfter)
	fmt.Printf("[I] %s:%d certificate duration of validity: %s\n", ip, port, durationToString(certificate.NotAfter.Sub(certificate.NotBefore)))
}
