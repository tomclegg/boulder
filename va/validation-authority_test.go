// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package va

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/test"
)

func bigIntFromB64(b64 string) *big.Int {
	bytes, _ := base64.URLEncoding.DecodeString(b64)
	x := big.NewInt(0)
	x.SetBytes(bytes)
	return x
}

func intFromB64(b64 string) int {
	return int(bigIntFromB64(b64).Int64())
}

var n = bigIntFromB64("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw==")
var e = intFromB64("AQAB")
var d = bigIntFromB64("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ==")
var p = bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")
var q = bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")

var TheKey = rsa.PrivateKey{
	PublicKey: rsa.PublicKey{N: n, E: e},
	D:         d,
	Primes:    []*big.Int{p, q},
}

var ident = core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "localhost"}

const expectedToken = "THETOKEN"
const pathWrongToken = "wrongtoken"
const path404 = "404"

func simpleSrv(t *testing.T, token string, stopChan, waitChan chan bool, enableTLS bool) {
	// Reset any existing handlers
	http.DefaultServeMux = http.NewServeMux()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, path404) {
			t.Logf("SIMPLESRV: Got a 404 req\n")
			http.NotFound(w, r)
		} else if strings.HasSuffix(r.URL.Path, pathWrongToken) {
			t.Logf("SIMPLESRV: Got a wrongtoken req\n")
			fmt.Fprintf(w, "wrongtoken")
		} else if strings.HasSuffix(r.URL.Path, "wait") {
			t.Logf("SIMPLESRV: Got a wait req\n")
			time.Sleep(time.Second * 3)
		} else if strings.HasSuffix(r.URL.Path, "wait-long") {
			t.Logf("SIMPLESRV: Got a wait-long req\n")
			time.Sleep(time.Second * 10)
		} else {
			t.Logf("SIMPLESRV: Got a valid req\n")
			fmt.Fprintf(w, "%s", token)
		}
	})

	server := &http.Server{Addr: "localhost:5001"}
	conn, err := net.Listen("tcp", server.Addr)
	if err != nil {
		waitChan <- true
		t.Fatalf("Couldn't listen on %s: %s", server.Addr, err)
	}

	go func() {
		<-stopChan
		conn.Close()
	}()

	var listener net.Listener
	if !enableTLS {
		listener = conn
	} else {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1337),
			Subject: pkix.Name{
				Organization: []string{"tests"},
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 1),

			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,

			DNSNames: []string{"example.com"},
		}

		certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &TheKey.PublicKey, &TheKey)
		cert := &tls.Certificate{
			Certificate: [][]byte{certBytes},
			PrivateKey:  &TheKey,
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*cert},
		}

		listener = tls.NewListener(conn, tlsConfig)
	}

	waitChan <- true
	server.Serve(listener)
}

func dvsniSrv(t *testing.T, R, S []byte, stopChan, waitChan chan bool) {
	RS := append(R, S...)
	z := sha256.Sum256(RS)
	zName := fmt.Sprintf("%064x.acme.invalid", z)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			Organization: []string{"tests"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 1),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames: []string{zName},
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &TheKey.PublicKey, &TheKey)
	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  &TheKey,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientAuth:   tls.NoClientCert,
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName == "wait-long.acme.invalid" {
				time.Sleep(time.Second * 10)
				return nil, nil
			}
			return cert, nil
		},
		NextProtos: []string{"http/1.1"},
	}

	httpsServer := &http.Server{Addr: "localhost:5001"}
	conn, err := net.Listen("tcp", httpsServer.Addr)
	if err != nil {
		waitChan <- true
		t.Fatalf("Couldn't listen on %s: %s", httpsServer.Addr, err)
	}
	tlsListener := tls.NewListener(conn, tlsConfig)

	go func() {
		<-stopChan
		conn.Close()
	}()

	waitChan <- true
	httpsServer.Serve(tlsListener)
}

func brokenTLSSrv(t *testing.T, stopChan, waitChan chan bool) {
	httpsServer := &http.Server{Addr: "localhost:5001"}
	conn, err := net.Listen("tcp", httpsServer.Addr)
	if err != nil {
		waitChan <- true
		t.Fatalf("Couldn't listen on %s: %s", httpsServer.Addr, err)
	}
	tlsListener := tls.NewListener(conn, &tls.Config{})

	go func() {
		<-stopChan
		conn.Close()
	}()

	waitChan <- true
	httpsServer.Serve(tlsListener)
}

func TestSimpleHttpTLS(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}

	chall := core.Challenge{Path: "test", Token: expectedToken}

	stopChan := make(chan bool, 1)
	waitChan := make(chan bool, 1)
	go simpleSrv(t, expectedToken, stopChan, waitChan, true)
	defer func() { stopChan <- true }()
	<-waitChan

	finChall := va.validateSimpleHTTP(ident, chall)
	test.Assert(t, finChall.Error == nil, chall.Path)
}

func TestSimpleHttp(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}

	tls := false
	chall := core.Challenge{Path: "test", Token: expectedToken, TLS: &tls}

	invalidChall := va.validateSimpleHTTP(ident, chall)
	test.AssertError(t, invalidChall.Error, "Server's not up yet; expected refusal. Where did we connect?")
	test.AssertEquals(t, invalidChall.Error.Type, core.ConnectionProblem)

	stopChan := make(chan bool, 1)
	waitChan := make(chan bool, 1)
	go simpleSrv(t, expectedToken, stopChan, waitChan, tls)
	defer func() { stopChan <- true }()
	<-waitChan

	finChall := va.validateSimpleHTTP(ident, chall)
	test.Assert(t, finChall.Error == nil, chall.Path)

	chall.Path = path404
	invalidChall = va.validateSimpleHTTP(ident, chall)
	test.AssertError(t, invalidChall.Error, "Should have found a 404 for the challenge.")
	test.AssertEquals(t, invalidChall.Error.Type, core.UnauthorizedProblem)

	chall.Path = pathWrongToken
	invalidChall = va.validateSimpleHTTP(ident, chall)
	test.AssertError(t, invalidChall.Error, "The path should have given us the wrong token.")
	test.AssertEquals(t, invalidChall.Error.Type, core.UnauthorizedProblem)

	chall.Path = ""
	invalidChall = va.validateSimpleHTTP(ident, chall)
	test.AssertError(t, invalidChall.Error, "Empty paths shouldn't work either.")
	test.AssertEquals(t, invalidChall.Error.Type, core.MalformedProblem)

	chall.Path = "validish"
	invalidChall = va.validateSimpleHTTP(core.AcmeIdentifier{Type: core.IdentifierType("ip"), Value: "127.0.0.1"}, chall)
	test.AssertError(t, invalidChall.Error, "IdentifierType IP shouldn't have worked.")
	test.AssertEquals(t, invalidChall.Error.Type, core.MalformedProblem)

	va.TestMode = false
	chall.Path = "alsoValidish"
	invalidChall = va.validateSimpleHTTP(core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "always.invalid"}, chall)
	test.AssertError(t, invalidChall.Error, "Domain name is invalid.")
	test.AssertEquals(t, invalidChall.Error.Type, core.UnknownHostProblem)
	va.TestMode = true

	chall.Path = "%"
	invalidChall = va.validateSimpleHTTP(ident, chall)
	test.AssertError(t, invalidChall.Error, "Path doesn't consist of URL-safe characters.")
	test.AssertEquals(t, invalidChall.Error.Type, core.MalformedProblem)

	chall.Path = "wait-long"
	started := time.Now()
	invalidChall = va.validateSimpleHTTP(ident, chall)
	took := time.Since(started)
	// Check that the HTTP connection times out after 5 seconds and doesn't block for 10 seconds
	test.Assert(t, (took > (time.Second * 5)), "HTTP timed out before 5 seconds")
	test.Assert(t, (took < (time.Second * 10)), "HTTP connection didn't timeout after 5 seconds")
	test.AssertError(t, invalidChall.Error, "Connection should've timed out")
	test.AssertEquals(t, invalidChall.Error.Type, core.ConnectionProblem)
}

func TestDvsni(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}

	a := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	ba := core.B64enc(a)
	chall := core.Challenge{R: ba, S: ba}

	invalidChall := va.validateDvsni(ident, chall)
	test.AssertError(t, invalidChall.Error, "Server's not up yet; expected refusal. Where did we connect?")
	test.AssertEquals(t, invalidChall.Error.Type, core.ConnectionProblem)

	waitChan := make(chan bool, 1)
	stopChan := make(chan bool, 1)
	go dvsniSrv(t, a, a, stopChan, waitChan)
	defer func() { stopChan <- true }()
	<-waitChan

	finChall := va.validateDvsni(ident, chall)
	test.Assert(t, finChall.Error == nil, chall.Path)

	invalidChall = va.validateDvsni(core.AcmeIdentifier{Type: core.IdentifierType("ip"), Value: "127.0.0.1"}, chall)
	test.AssertError(t, invalidChall.Error, "IdentifierType IP shouldn't have worked.")
	test.AssertEquals(t, invalidChall.Error.Type, core.MalformedProblem)

	va.TestMode = false
	invalidChall = va.validateDvsni(core.AcmeIdentifier{Type: core.IdentifierDNS, Value: "always.invalid"}, chall)
	test.AssertError(t, invalidChall.Error, "Domain name is invalid.")
	test.AssertEquals(t, invalidChall.Error.Type, core.UnknownHostProblem)
	va.TestMode = true

	chall.R = ba[5:]
	invalidChall = va.validateDvsni(ident, chall)
	test.AssertError(t, invalidChall.Error, "R Should be illegal Base64")
	test.AssertEquals(t, invalidChall.Error.Type, core.MalformedProblem)

	chall.R = ba
	chall.S = "!@#"
	invalidChall = va.validateDvsni(ident, chall)
	test.AssertError(t, invalidChall.Error, "S Should be illegal Base64")
	test.AssertEquals(t, invalidChall.Error.Type, core.MalformedProblem)

	chall.S = ba
	chall.Nonce = "wait-long"
	started := time.Now()
	invalidChall = va.validateDvsni(ident, chall)
	took := time.Since(started)
	// Check that the HTTP connection times out after 5 seconds and doesn't block for 10 seconds
	test.Assert(t, (took > (time.Second * 5)), "HTTP timed out before 5 seconds")
	test.Assert(t, (took < (time.Second * 10)), "HTTP connection didn't timeout after 5 seconds")
	test.AssertError(t, invalidChall.Error, "Connection should've timed out")
	test.AssertEquals(t, invalidChall.Error.Type, core.ConnectionProblem)
}

func TestTLSError(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}

	a := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	ba := core.B64enc(a)
	chall := core.Challenge{R: ba, S: ba}

	waitChan := make(chan bool, 1)
	stopChan := make(chan bool, 1)
	go brokenTLSSrv(t, stopChan, waitChan)
	defer func() { stopChan <- true }()
	<-waitChan

	invalidChall := va.validateDvsni(ident, chall)
	test.AssertError(t, invalidChall.Error, "What cert was used?")
	test.AssertEquals(t, invalidChall.Error.Type, core.TLSProblem)
}

func TestValidateHTTP(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	tls := false
	challHTTP := core.SimpleHTTPChallenge()
	challHTTP.Path = "test"
	challHTTP.TLS = &tls

	stopChanHTTP := make(chan bool, 1)
	waitChanHTTP := make(chan bool, 1)
	go simpleSrv(t, challHTTP.Token, stopChanHTTP, waitChanHTTP, tls)

	// Let them start
	<-waitChanHTTP

	// shutdown cleanly
	defer func() {
		stopChanHTTP <- true
	}()

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{challHTTP},
	}
	va.validate(authz, 0)

	test.AssertEquals(t, core.StatusValid, mockRA.lastAuthz.Challenges[0].Status)
}

func TestValidateDvsni(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	challDvsni := core.DvsniChallenge()
	challDvsni.S = challDvsni.R

	waitChanDvsni := make(chan bool, 1)
	stopChanDvsni := make(chan bool, 1)
	ar, _ := core.B64dec(challDvsni.R)
	as, _ := core.B64dec(challDvsni.S)
	go dvsniSrv(t, ar, as, stopChanDvsni, waitChanDvsni)

	// Let them start
	<-waitChanDvsni

	// shutdown cleanly
	defer func() {
		stopChanDvsni <- true
	}()

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{challDvsni},
	}
	va.validate(authz, 0)

	test.AssertEquals(t, core.StatusValid, mockRA.lastAuthz.Challenges[0].Status)
}

func TestValidateDvsniNotSane(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	challDvsni := core.DvsniChallenge()
	challDvsni.R = "boulder" // Not a sane thing to do.

	waitChanDvsni := make(chan bool, 1)
	stopChanDvsni := make(chan bool, 1)
	ar, _ := core.B64dec(challDvsni.R)
	as, _ := core.B64dec(challDvsni.S)
	go dvsniSrv(t, ar, as, stopChanDvsni, waitChanDvsni)

	// Let them start
	<-waitChanDvsni

	// shutdown cleanly
	defer func() {
		stopChanDvsni <- true
	}()

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{challDvsni},
	}
	va.validate(authz, 0)

	test.AssertEquals(t, core.StatusInvalid, mockRA.lastAuthz.Challenges[0].Status)
}

func TestUpdateValidations(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	tls := false
	challHTTP := core.SimpleHTTPChallenge()
	challHTTP.Path = "wait"
	challHTTP.TLS = &tls

	stopChanHTTP := make(chan bool, 1)
	waitChanHTTP := make(chan bool, 1)
	go simpleSrv(t, challHTTP.Token, stopChanHTTP, waitChanHTTP, tls)

	// Let them start
	<-waitChanHTTP

	// shutdown cleanly
	defer func() {
		stopChanHTTP <- true
	}()

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{challHTTP},
	}

	started := time.Now()
	va.UpdateValidations(authz, 0)
	took := time.Since(started)

	// Check that the call to va.UpdateValidations didn't block for 3 seconds
	test.Assert(t, (took < (time.Second * 3)), "UpdateValidations blocked")
}

func TestCAAChecking(t *testing.T) {
	type CAATest struct {
		Domain  string
		Present bool
		Valid   bool
	}
	tests := []CAATest{
		// Reserved
		CAATest{"reserved.com", true, false},
		// Critical
		CAATest{"critical.com", true, false},
		// Good (absent)
		CAATest{"absent.com", false, true},
		// Good (present)
		CAATest{"present.com", true, true},
	}

	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}
	va.IssuerDomain = "letsencrypt.org"
	for _, caaTest := range tests {
		present, valid, err := va.CheckCAARecords(core.AcmeIdentifier{Type: "dns", Value: caaTest.Domain})
		test.AssertNotError(t, err, caaTest.Domain)
		fmt.Println(caaTest.Domain, caaTest.Present == present, caaTest.Valid == valid)
		test.AssertEquals(t, caaTest.Present, present)
		test.AssertEquals(t, caaTest.Valid, valid)
	}

	present, valid, err := va.CheckCAARecords(core.AcmeIdentifier{Type: "dns", Value: "dnssec-failed.org"})
	test.AssertError(t, err, "dnssec-failed.org")
	test.Assert(t, !present, "Present should be false")
	test.Assert(t, !valid, "Valid should be false")
}

func TestDNSValidationFailure(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	chalDNS := core.DNSChallenge()

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chalDNS},
	}
	va.validate(authz, 0)

	t.Logf("Resulting Authz: %+v", authz)
	test.AssertNotNil(t, mockRA.lastAuthz, "Should have gotten an authorization")
	test.Assert(t, authz.Challenges[0].Status == core.StatusInvalid, "Should be invalid.")
	test.AssertEquals(t, authz.Challenges[0].Error.Type, core.UnauthorizedProblem)
}

func TestDNSValidationInvalid(t *testing.T) {
	var notDNS = core.AcmeIdentifier{
		Type:  core.IdentifierType("iris"),
		Value: "790DB180-A274-47A4-855F-31C428CB1072",
	}

	chalDNS := core.DNSChallenge()

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     notDNS,
		Challenges:     []core.Challenge{chalDNS},
	}

	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	va.validate(authz, 0)

	test.AssertNotNil(t, mockRA.lastAuthz, "Should have gotten an authorization")
	test.Assert(t, authz.Challenges[0].Status == core.StatusInvalid, "Should be invalid.")
	test.AssertEquals(t, authz.Challenges[0].Error.Type, core.MalformedProblem)
}

func TestDNSValidationNotSane(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	chal0 := core.DNSChallenge()
	chal0.Token = ""

	chal1 := core.DNSChallenge()
	chal1.Token = "yfCBb-bRTLz8Wd1C0lTUQK3qlKj3-t2tYGwx5Hj7r_"

	chal2 := core.DNSChallenge()
	chal2.R = "1"

	chal3 := core.DNSChallenge()
	chal3.S = "2"

	chal4 := core.DNSChallenge()
	chal4.Nonce = "2"

	chal5 := core.DNSChallenge()
	var tls = true
	chal5.TLS = &tls

	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chal0, chal1, chal2, chal3, chal4, chal5},
	}

	for i := 0; i < 6; i++ {
		va.validate(authz, i)
		test.AssertEquals(t, authz.Challenges[i].Status, core.StatusInvalid)
		test.AssertEquals(t, authz.Challenges[i].Error.Type, core.MalformedProblem)
	}
}

func TestDNSValidationBadDNSSEC(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = &mocks.MockDNS{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	chalDNS := core.DNSChallenge()

	badDNSSEC := core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "dnssec-failed.org",
	}
	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     badDNSSEC,
		Challenges:     []core.Challenge{chalDNS},
	}
	va.validate(authz, 0)

	test.AssertNotNil(t, mockRA.lastAuthz, "Should have gotten an authorization")
	test.Assert(t, authz.Challenges[0].Status == core.StatusInvalid, "Should be invalid.")
	test.AssertEquals(t, authz.Challenges[0].Error.Type, core.DNSSECProblem)
}

func TestDNSValidationNoServer(t *testing.T) {
	va := NewValidationAuthorityImpl(true)
	va.DNSResolver = core.NewDNSResolverImpl(time.Second*5, []string{})
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	chalDNS := core.DNSChallenge()
	var authz = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     ident,
		Challenges:     []core.Challenge{chalDNS},
	}
	va.validate(authz, 0)

	test.AssertNotNil(t, mockRA.lastAuthz, "Should have gotten an authorization")
	test.Assert(t, authz.Challenges[0].Status == core.StatusInvalid, "Should be invalid.")
	test.AssertEquals(t, authz.Challenges[0].Error.Type, core.ServerInternalProblem)
}

// TestDNSValidationLive is an integration test, depending on
// the existance of some Internet resources. Because of that,
// it asserts nothing; it is intended for coverage.
func TestDNSValidationLive(t *testing.T) {
	va := NewValidationAuthorityImpl(false)
	va.DNSResolver = &mocks.MockDNS{}
	mockRA := &MockRegistrationAuthority{}
	va.RA = mockRA

	goodChalDNS := core.DNSChallenge()
	// This token is set at _acme-challenge.good.bin.coffee
	goodChalDNS.Token = "yfCBb-bRTLz8Wd1C0lTUQK3qlKj3-t2tYGwx5Hj7r_w"

	var goodIdent = core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: "good.bin.coffee",
	}

	var badIdent = core.AcmeIdentifier{
		Type:  core.IdentifierType("dns"),
		Value: "bad.bin.coffee",
	}

	var authzGood = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     goodIdent,
		Challenges:     []core.Challenge{goodChalDNS},
	}

	va.validate(authzGood, 0)

	if authzGood.Challenges[0].Status != core.StatusValid {
		t.Logf("TestDNSValidationLive on Good did not succeed.")
	}

	badChalDNS := core.DNSChallenge()
	// This token is NOT set at _acme-challenge.bad.bin.coffee
	badChalDNS.Token = "yfCBb-bRTLz8Wd1C0lTUQK3qlKj3-t2tYGwx5Hj7r_w"

	var authzBad = core.Authorization{
		ID:             core.NewToken(),
		RegistrationID: 1,
		Identifier:     badIdent,
		Challenges:     []core.Challenge{badChalDNS},
	}

	va.validate(authzBad, 0)
	if authzBad.Challenges[0].Status != core.StatusInvalid {
		t.Logf("TestDNSValidationLive on Bad did succeed inappropriately.")
	}

}

type MockRegistrationAuthority struct {
	lastAuthz *core.Authorization
}

func (ra *MockRegistrationAuthority) NewRegistration(reg core.Registration) (core.Registration, error) {
	return reg, nil
}

func (ra *MockRegistrationAuthority) NewAuthorization(authz core.Authorization, regID int64) (core.Authorization, error) {
	return authz, nil
}

func (ra *MockRegistrationAuthority) NewCertificate(req core.CertificateRequest, regID int64) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ra *MockRegistrationAuthority) UpdateRegistration(reg core.Registration, updated core.Registration) (core.Registration, error) {
	return reg, nil
}

func (ra *MockRegistrationAuthority) UpdateAuthorization(authz core.Authorization, foo int, challenge core.Challenge) (core.Authorization, error) {
	return authz, nil
}

func (ra *MockRegistrationAuthority) RevokeCertificate(cert x509.Certificate) error {
	return nil
}

func (ra *MockRegistrationAuthority) OnValidationUpdate(authz core.Authorization) error {
	ra.lastAuthz = &authz
	return nil
}
