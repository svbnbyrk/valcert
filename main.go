package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

func main() {
	args := os.Args[1:]
	r, _ := regexp.MatchString(`[^\s.]+(?:\.[a-z]+)*(?::\d+)`, args[0])
	if !r || len(args) > 1 || args[0] == "-help" {
		fmt.Println("Usage: valcert example.com:443")
	} else {
		hn := strings.Split(args[0], ":")[0]

		conn, err := tls.Dial("tcp", args[0], nil)
		if err != nil {
			panic("Server doesn't support SSL certificate err: " + err.Error())
		}
		fmt.Printf("%s support SSL certificate\n", hn)

		err = conn.VerifyHostname(hn)
		if err != nil {
			panic("Hostname doesn't match with certificate: " + err.Error())
		}
		fmt.Printf("%s match with certificate\n", hn)

		expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
		fmt.Printf("Issuer: %s\n", conn.ConnectionState().PeerCertificates[0].Issuer)

		today := time.Now()

		if expiry.After(today) {
			d := expiry.Sub(today).Hours() / 24

			fmt.Printf("Expiry: %v\nYour certificate expires in %.1f days.", expiry.Format(time.RFC850), d)
			if d > 7 {
				fmt.Printf(" Please contact your Certificate Authority (CA)\n")
			}
		} else {
			fmt.Printf("Expiry: %v\nYour certificate has expired. Contact the Certificate Authority (CA)\n", expiry.Format(time.RFC850))
		}
	}
}
