package main

import (
	"fmt"
	"strings"
	"time"
)

type TlsV3ServerHello struct {
	Protocol    SslProtocol
	Ciphersuite Ciphersuite
	Time        time.Time
	SessionId   []byte
}

func (serverhello *TlsV3ServerHello) parse(data []byte) (TlsV3ServerHello, []byte) {
	cnt := 0
	_, cnt = nextBytes(data, cnt, 1)                          // ServerHello message type
	messageLength, cnt := nextBytes(data, cnt, 3)             // Message length
	serverhello.Protocol.Value, cnt = nextBytes(data, cnt, 2) // SSL version
	randomLengthHex, cnt := nextBytes(data, cnt, 4)           // First 4 bytes of random (Unix time)
	serverhello.Time = time.Unix(int64(bytesToInt(randomLengthHex)), 0)
	_, cnt = nextBytes(data, cnt, 28)                                              // Last 28 bytes of the random number
	sessionidlength, cnt := nextBytes(data, cnt, 1)                                // Session Id length
	serverhello.SessionId, cnt = nextBytes(data, cnt, bytesToInt(sessionidlength)) // Session Id
	serverhello.Ciphersuite.Value, cnt = nextBytes(data, cnt, 2)                   // CipherSuite
	_, cnt = nextBytes(data, cnt, 1)                                               // Selected compression method
	if bytesToInt(messageLength) > cnt {
		extentionlength, ncnt := nextBytes(data, cnt, 2) // Extensions length
		cnt = ncnt
		_, cnt = nextBytes(data, cnt, bytesToInt(extentionlength)) // Extensions
	}
	return *serverhello, data[cnt:]
}

func (shello *TlsV3ServerHello) String() string {
	lines := []string{}
	lines = append(lines, "[+] TlsV3ServerHello")
	lines = append(lines, fmt.Sprintf("    Protocol: %s", shello.Protocol.String()))
	lines = append(lines, fmt.Sprintf("    Time: %s", shello.Time))
	lines = append(lines, fmt.Sprintf("    SessionID: %x", shello.SessionId))
	lines = append(lines, fmt.Sprintf("    Ciphersuite: %s", shello.Ciphersuite.String()))
	return strings.Join(lines, "\n")
}
