package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
)

func get_len_and_hex(lensize int, heximp ...[]byte) []byte {
	hexbuff := []byte{}
	for _, h := range heximp {
		hexbuff = append(hexbuff, h...)
	}
	hexlen := fmt.Sprintf("%x", len(hexbuff))
	for len(hexlen) < (lensize * 2) {
		hexlen = "0" + hexlen
	}
	hexlen_hex, _ := hex.DecodeString(string(hexlen))
	return append(hexlen_hex, hexbuff...)
}

func getRandomBytes(length int) []byte {
	myBytes := make([]byte, length)
	rand.Read(myBytes)
	return myBytes
}

func ifAppend(keep bool, heximp ...[]byte) []byte {
	if !keep {
		return []byte{}
	}
	hex := []byte{}
	for _, h := range heximp {
		hex = append(hex, h...)
	}
	return hex
}

func getBytesFromSocket(socket net.Conn, length int) []byte {
	buffer := make([]byte, length)
	socket.SetReadDeadline(time.Now().Add(time.Second * 5)) // Set timeout
	numBytesRead, err := socket.Read(buffer)
	if err != nil {
		return []byte{}
	}
	return buffer[0:numBytesRead]
}

func bytesToInt(data []byte) int {
	retval := 0
	for _, b := range data {
		retval = (retval << 8) + int(b)
	}
	return retval
}

func nextBytes(data []byte, cnt int, length int) ([]byte, int) {
	return data[cnt : cnt+length], cnt + length
}

func hdump(val []byte) {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer stdoutDumper.Close()
	stdoutDumper.Write(val)
}

func intToBytes(length int, val int) []byte {
	retval := []byte{}
	// prepend bytewise
	for val > 255 {
		retval = append([]byte{byte(val)}, retval...)
		val = (val >> 8)
	}
	retval = append([]byte{byte(val)}, retval...)
	// fill with leading zeros
	for len(retval) < length {
		retval = append([]byte{0x00}, retval...)
	}
	// cutoff the beginning, if to long
	return retval[len(retval)-length:]
}

func durationToString(d time.Duration) string {
	t := time.Time{}
	t = t.Add(d)
	return fmt.Sprintf("%dy %dm %dd %dh %dm", t.Year()-1, t.Month()-1, t.Day()-1, t.Hour(), t.Minute())
}
