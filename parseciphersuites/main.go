package main

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

func main() {
	mapLines := []string{}
	fileScanner := bufio.NewScanner(strings.NewReader(cipherlist))
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		line := fileScanner.Text()
		r := regexp.MustCompile(`(?:SSL3|TLS1)_CK_(\S+)\s+0x0300([0-9A-Fa-f]{4})`)
		if r.MatchString(line) {
			values := r.FindStringSubmatch(line)
			mapLines = append(mapLines, makeMapLine(strings.ToLower(values[2]), values[1]))
		}
		r = regexp.MustCompile(`SSL2_CK_(\S+)\s+0x02([0-9A-Fa-f]{6})`)
		if r.MatchString(line) {
			values := r.FindStringSubmatch(line)
			mapLines = append(mapLines, makeMapLine(strings.ToLower(values[2]), values[1]))
		}

		r = regexp.MustCompile(`^0x([0-9a-fA-F]{4})\s+(?:SSL|TLS)_(\S+)`)
		if r.MatchString(line) {
			values := r.FindStringSubmatch(line)
			mapLines = append(mapLines, makeMapLine(strings.ToLower(values[1]), values[2]))
		}

	}

	fmt.Println("package main")
	fmt.Print("var CipherNameMap = map[string]string{")
	fmt.Print(strings.Join(mapLines, ", \n"))

	fmt.Println("}")

}

func makeMapLine(hexString string, nameString string) string {
	retval := []string{}
	for i := 0; i < len(hexString); i += 2 {
		retval = append(retval, fmt.Sprintf("0x%s", hexString[i:i+2]))
	}
	return "string([]byte{" + strings.Join(retval, ", ") + "}):\"" + nameString + "\""
}
