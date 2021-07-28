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
		start := conn.ConnectionState().PeerCertificates[0].NotBefore
		fmt.Printf("Issuer: %s\n", conn.ConnectionState().PeerCertificates[0].Issuer)

		today := time.Now()
		d := expiry.Sub(today).Hours() / 24
		//CAB forum’s baseline requirements.
		sed := time.Date(2020, time.September, 1, 0, 0, 0, 0, time.Now().UTC().Location())

		if expiry.After(today) {
			fmt.Printf("Expiry: %v\nYour certificate expires in %.1f days.", expiry.Format(time.RFC850), d)
			if start.After(sed) {
				if d > 398 {		
					fmt.Printf("Certificates issued after September 1, 2020 should have validity periods no longer than 398 days.")			
					fmt.Printf(" Please contact your Certificate Authority (CA)\n")					
				}
			}
			if d < 14 {
				fmt.Printf(" Please contact your Certificate Authority (CA)\n")
			}
		} else {
			fmt.Printf("Expiry: %v\nYour certificate has expired. Contact the Certificate Authority (CA)\n", expiry.Format(time.RFC850))
		}
	}
}
