package main

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
)

type TlsV3ServerResponse struct {
	Protocol    SslProtocol
	ServerHello TlsV3ServerHello
	Certificate []x509.Certificate
}

func (shello *TlsV3ServerResponse) read(socket net.Conn) (*TlsV3ServerResponse, error) {
	data := getBytesFromSocket(socket, 5)
	if len(data) == 0 {
		return nil, ErrorRecordProtocolUnknown
	}
	running := true
	for running { // some servers have a header for each message

		switch data[0] {
		case 0x16:
		case 0x15:
			return nil, ErrorRecordProtocolAlert
		default:
			return nil, ErrorRecordProtocolUnknown
		}
		shello.Protocol.Value = data[1:3]
		servermessagelength := bytesToInt(data[3:5])
		servermessagehex := getBytesFromSocket(socket, servermessagelength)
		for len(servermessagehex) > 0 {
			switch servermessagehex[0] {
			case 0x00: // Hello Request
				/*
					When this message will be sent:
					   The HelloRequest message MAY be sent by the server at any time.

					Meaning of this message:
						HelloRequest is a simple notification that the client should begin
						the negotiation process anew.  In response, the client should send
						a ClientHello message when convenient.  This message is not
						intended to establish which side is the client or server but
						merely to initiate a new negotiation.  Servers SHOULD NOT send a
						HelloRequest immediately upon the client's initial connection.  It
						is the client's job to send a ClientHello at that time.

						This message will be ignored by the client if the client is
						currently negotiating a session.  This message MAY be ignored by
						the client if it does not wish to renegotiate a session, or the
						client may, if it wishes, respond with a no_renegotiation alert.
						Since handshake messages are intended to have transmission
						precedence over application data, it is expected that the
						negotiation will begin before no more than a few records are
						received from the client.  If the server sends a HelloRequest but
						does not receive a ClientHello in response, it may close the
						connection with a fatal alert.
						After sending a HelloRequest, servers SHOULD NOT repeat the
						request until the subsequent handshake negotiation is complete.

					https://tools.ietf.org/html/rfc5246#section-7.4.1.1
				*/
				length := bytesToInt(servermessagehex[1:4])
				servermessagehex = servermessagehex[length+4:]
			case 0x02: // Server Hello
				shello.ServerHello, servermessagehex = shello.ServerHello.parse(servermessagehex)
			case 0x0b: // Certificate
				shello.Certificate, servermessagehex = parseX509Certificate(servermessagehex)
			case 0x0c: // Server Key Exchange
				length := bytesToInt(servermessagehex[1:4])
				servermessagehex = servermessagehex[length+4:] // dont parse, just cut off the data
			case 0x0e: // Server Hello Done
				length := bytesToInt(servermessagehex[1:4])
				servermessagehex = servermessagehex[length+4:] // dont parse, just cut off the data
				running = false
			default:
				servermessagehex = []byte{}
				// if we reach this, the server wants us to parse something unknown, we ignore it
			}
		}
		if running {
			data = getBytesFromSocket(socket, 5)
			if len(data) < 5 {
				running = false
			}
		}

	}
	return shello, nil
}

func (shello *TlsV3ServerResponse) String() string {
	lines := []string{}
	lines = append(lines, fmt.Sprintf("Protocol: %s", shello.Protocol.String()))
	scanner := bufio.NewScanner(strings.NewReader(shello.ServerHello.String()))
	for scanner.Scan() {
		lines = append(lines, fmt.Sprintf("  %s", scanner.Text()))
	}
	for _, cert := range shello.Certificate {
		scanner := bufio.NewScanner(strings.NewReader(X509CertificateString(cert)))
		for scanner.Scan() {
			lines = append(lines, fmt.Sprintf("  %s", scanner.Text()))
		}
	}
	return strings.Join(lines, "\n")
}
