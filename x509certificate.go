package main

import (
	"crypto/x509"
	"fmt"
	"strings"
)

func parseX509Certificate(data []byte) ([]x509.Certificate, []byte) {
	certificates := []x509.Certificate{}
	cnt := 0
	_, cnt = nextBytes(data, cnt, 1)                      // Certificate message type
	_, cnt = nextBytes(data, cnt, 3)                      // Message length
	certificatesLengthHex, cnt := nextBytes(data, cnt, 3) // Certificates length
	certificateLengthSum := 0
	var certificateLengthHex []byte
	var certdata []byte
	for certificateLengthSum < bytesToInt(certificatesLengthHex) {
		certificateLengthHex, cnt = nextBytes(data, cnt, 3)                    // Certificate length
		certdata, cnt = nextBytes(data, cnt, bytesToInt(certificateLengthHex)) // Certificate data
		certificate, _ := x509.ParseCertificate(certdata)
		certificates = append(certificates, *certificate)
		certificateLengthSum = certificateLengthSum + bytesToInt(certificateLengthHex) + 3
	}
	return certificates, data[cnt:]
}

func X509CertificateString(cert x509.Certificate) string {
	lines := []string{}
	lines = append(lines, "[+] Certificate")
	lines = append(lines, fmt.Sprintf("    Version: %d", cert.PublicKeyAlgorithm))
	lines = append(lines, fmt.Sprintf("    Signature Algorithm: %s", cert.SignatureAlgorithm))
	lines = append(lines, fmt.Sprintf("    Signature Length: %d", len(cert.Signature)))
	lines = append(lines, fmt.Sprintf("    PublicKey Algorithm: %s", cert.PublicKeyAlgorithm))
	lines = append(lines, fmt.Sprintf("    Issuer: %s", cert.Issuer))
	lines = append(lines, fmt.Sprintf("    Subject: %s", cert.Subject))
	lines = append(lines, fmt.Sprintf("    Not Before: %s", cert.NotBefore))
	lines = append(lines, fmt.Sprintf("    Not After: %s", cert.NotAfter))
	return strings.Join(lines, "\n")
}
