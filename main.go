package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/svbnbyrk/validate-ssl-cert/revoke"
)

func main() {
	args := os.Args[1:]
	r, _ := regexp.MatchString(`[^\s.]+(?:\.[a-z]+)*?::\d+`, args[0])
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
		fmt.Println("Certificates:")
		for i := 0; i < len(conn.ConnectionState().PeerCertificates); i++ {
			cert := conn.ConnectionState().PeerCertificates[i]
			isRevoke, ok, _ := revoke.VerifyCertificate(cert)
			if ok != true {
				fmt.Println("Certificate revocation check could not be completed.")
			}
			if isRevoke == true {
				fmt.Println("Certificate is revoked.")
			}
			expiry := cert.NotAfter
			start := cert.NotBefore
			issuer := cert.Issuer
			subject := cert.Subject
			fmt.Printf("\nIssuer: %s", issuer)
			fmt.Printf("\nSubject: %s", subject)
			if issuer.CommonName == subject.CommonName {
				fmt.Println("Certificate is Self signed. Please contact your Certificate Authority (CA)")
			}
			today := time.Now()
			d := expiry.Sub(today).Hours() / 24
			//CAB forum’s baseline requirements.
			sed := time.Date(2020, time.September, 1, 0, 0, 0, 0, time.Now().UTC().Location())

			if expiry.After(today) {
				fmt.Printf("\nExpiry: %v\nYour certificate expires in %.1f days.", expiry.Format(time.RFC850), d)
				if start.After(sed) {
					if d > 398 {
						fmt.Printf("\nCertificates issued after September 1, 2020 should have validity periods no longer than 398 days.")
						fmt.Printf("Please contact your Certificate Authority (CA)")
					}
				}
				if d < 14 {
					fmt.Printf("\nPlease contact your Certificate Authority (CA)")
				}
			} else {
				fmt.Printf("\nExpiry: %v\nYour certificate has expired. Contact the Certificate Authority (CA)", expiry.Format(time.RFC850))
			}
			fmt.Println("\n***************************")
		}
	}
}
