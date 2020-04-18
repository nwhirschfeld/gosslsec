package main

import (
	"errors"
)

var ErrorRecordProtocolAlert = errors.New("The TLS Record header has the type \"ALERT\"")
var ErrorRecordProtocolUnknown = errors.New("The TLS Record header has an unknown type")
var ErrorNotSSLV2ServerHello = errors.New("Recived something, thats not an SSLv3 server hello")
var ErrorCannotConnect = errors.New("Cannot connect to port")
