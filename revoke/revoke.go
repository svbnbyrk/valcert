// Package revoke provides functionality for checking the validity of
// a cert. Specifically, the temporal validity of the certificate is
// checked first, then any CRL and OCSP url in the cert is checked.
package revoke

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io"
	"io/ioutil"
	"net/http"
	neturl "net/url"
	"sync"
	"time"
)

// HTTPClient is an instance of http.Client that will be used for all HTTP requests.
var HTTPClient = http.DefaultClient

// CRLSet associates a PKIX certificate list with the URL the CRL is
// fetched from.
var CRLSet = map[string]*pkix.CertificateList{}
var crlLock = new(sync.Mutex)

// We can't handle LDAP certificates, so this checks to see if the
// URL string points to an LDAP resource so that we can ignore it.
func ldapURL(url string) bool {
	u, err := neturl.Parse(url)
	if err != nil {
		fmt.Printf("error parsing url %s: %v", url, err)
		return false
	}
	if u.Scheme == "ldap" {
		return true
	}
	return false
}

// revCheck should check the certificate for any revocations.
// This leads to the following combinations:
//
//  false, false: an error was encountered while checking revocations.
//
//  false, true:  the certificate was checked successfully, and it is not revoked.
//
//  true, true:   the certificate was checked successfully, and  it is revoked.
//
//  true, false:  failure to check revocation status causes verification to fail
func revCheck(cert *x509.Certificate) (revoked, ok bool, err error) {
	for _, url := range cert.CRLDistributionPoints {
		if ldapURL(url) {
			fmt.Printf("skipping LDAP CRL: %s", url)
			continue
		}

		if revoked, ok, err := certIsRevokedCRL(cert, url); !ok {
			fmt.Printf("error checking revocation via CRL")
			return false, false, err
		} else if revoked {
			fmt.Printf("certificate is revoked via CRL")
			return true, true, err
		}
	}

	if revoked, ok, err := certIsRevokedOCSP(cert); !ok {
		fmt.Printf("error checking revocation via OCSP")
		return false, false, err
	} else if revoked {
		fmt.Printf("certificate is revoked via OCSP")
		return true, true, err
	}

	return false, true, nil
}

// fetchCRL fetches and parses a CRL.
func fetchCRL(url string) (*pkix.CertificateList, error) {
	resp, err := HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode >= 300 {
		return nil, errors.New("failed to retrieve CRL")
	}

	body, err := crlRead(resp.Body)
	if err != nil {
		return nil, err
	}
	return x509.ParseCRL(body)
}

func getIssuer(cert *x509.Certificate) *x509.Certificate {
	var issuer *x509.Certificate
	var err error
	for _, issuingCert := range cert.IssuingCertificateURL {
		issuer, err = fetchRemote(issuingCert)
		if err != nil {
			continue
		}
		break
	}

	return issuer

}

// check a cert against a specific CRL. Returns the same bool pair
// as revCheck, plus an error if one occurred.
func certIsRevokedCRL(cert *x509.Certificate, url string) (revoked, ok bool, err error) {
	crlLock.Lock()
	crl, ok := CRLSet[url]
	if ok && crl == nil {
		ok = false
		delete(CRLSet, url)
	}
	crlLock.Unlock()

	var shouldFetchCRL = true
	if ok {
		if !crl.HasExpired(time.Now()) {
			shouldFetchCRL = false
		}
	}

	issuer := getIssuer(cert)

	if shouldFetchCRL {
		var err error
		crl, err = fetchCRL(url)
		if err != nil {
			fmt.Printf("failed to fetch CRL: %v", err)
			return false, false, err
		}

		// check CRL signature
		if issuer != nil {
			err = issuer.CheckCRLSignature(crl)
			if err != nil {
				fmt.Printf("failed to verify CRL: %v", err)
				return false, false, err
			}
		}

		crlLock.Lock()
		CRLSet[url] = crl
		crlLock.Unlock()
	}

	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			fmt.Printf("Serial number match: intermediate is revoked.")
			return true, true, err
		}
	}

	return false, true, err
}

// VerifyCertificate ensures that the certificate passed in hasn't
// expired and checks the CRL for the server.
func VerifyCertificate(cert *x509.Certificate) (revoked, ok bool, err error) {
	return revCheck(cert)
}

func fetchRemote(url string) (*x509.Certificate, error) {
	resp, err := HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	in, err := remoteRead(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(in)
}

var ocspOpts = ocsp.RequestOptions{
	Hash: crypto.SHA1,
}

func certIsRevokedOCSP(leaf *x509.Certificate) (revoked, ok bool, e error) {
	var err error

	ocspURLs := leaf.OCSPServer
	if len(ocspURLs) == 0 {
		// OCSP not enabled for this certificate.
		return false, true, nil
	}

	issuer := getIssuer(leaf)

	if issuer == nil {
		return false, false, nil
	}

	ocspRequest, err := ocsp.CreateRequest(leaf, issuer, &ocspOpts)
	if err != nil {
		return revoked, ok, err
	}

	for _, server := range ocspURLs {
		resp, err := sendOCSPRequest(server, ocspRequest, leaf, issuer)
		// There wasn't an error fetching the OCSP status.
		ok = true

		if resp.Status != ocsp.Good {
			// The certificate was revoked.
			revoked = true
		}

		return revoked, ok, err
	}
	return revoked, ok, err
}

// sendOCSPRequest attempts to request an OCSP response from the
// server. The error only indicates a failure to *fetch* the
// certificate, and *does not* mean the certificate is valid.
func sendOCSPRequest(server string, req []byte, leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	var resp *http.Response
	var err error
	if len(req) > 256 {
		buf := bytes.NewBuffer(req)
		resp, err = HTTPClient.Post(server, "application/ocsp-request", buf)
	} else {
		reqURL := server + "/" + neturl.QueryEscape(base64.StdEncoding.EncodeToString(req))
		resp, err = HTTPClient.Get(reqURL)
	}

	if err != nil {
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve OSCP")
	}

	body, err := ocspRead(resp.Body)
	if err != nil {
		return nil, err
	}

	switch {
	case bytes.Equal(body, ocsp.UnauthorizedErrorResponse):
		return nil, errors.New("OSCP unauthorized")
	case bytes.Equal(body, ocsp.MalformedRequestErrorResponse):
		return nil, errors.New("OSCP malformed")
	case bytes.Equal(body, ocsp.InternalErrorErrorResponse):
		return nil, errors.New("OSCP internal error")
	case bytes.Equal(body, ocsp.TryLaterErrorResponse):
		return nil, errors.New("OSCP try later")
	case bytes.Equal(body, ocsp.SigRequredErrorResponse):
		return nil, errors.New("OSCP signature required")
	}

	return ocsp.ParseResponseForCert(body, leaf, issuer)
}

var crlRead = ioutil.ReadAll

var remoteRead = ioutil.ReadAll

var ocspRead = ioutil.ReadAll
