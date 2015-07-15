// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package va

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"
)

// ValidationAuthorityImpl represents a VA
type ValidationAuthorityImpl struct {
	RA           core.RegistrationAuthority
	log          *blog.AuditLogger
	DNSResolver  core.DNSResolver
	IssuerDomain string
	TestMode     bool
	UserAgent    string
}

// NewValidationAuthorityImpl constructs a new VA, and may place it
// into Test Mode (tm)
func NewValidationAuthorityImpl(tm bool) ValidationAuthorityImpl {
	logger := blog.GetAuditLogger()
	logger.Notice("Validation Authority Starting")
	return ValidationAuthorityImpl{log: logger, TestMode: tm}
}

// Used for audit logging
type verificationRequestEvent struct {
	ID           string         `json:",omitempty"`
	Requester    int64          `json:",omitempty"`
	Challenge    core.Challenge `json:",omitempty"`
	RequestTime  time.Time      `json:",omitempty"`
	ResponseTime time.Time      `json:",omitempty"`
	Error        string         `json:",omitempty"`
}

func (va ValidationAuthorityImpl) debugValidation(vType string, identifier core.AcmeIdentifier, challenge *core.Challenge) {
	va.log.Debug(fmt.Sprintf("validate%s: [%s] challenge %+v", vType, identifier, challenge))
}


// Validation methods

func (va ValidationAuthorityImpl) validateSimpleHTTP(identifier core.AcmeIdentifier, input core.Challenge) (challenge core.Challenge) {
	challenge = input
	challenge.Error = nil
	defer va.debugValidation("SimpleHTTP", identifier, &challenge)

	if len(challenge.Path) == 0 {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "No path provided for SimpleHTTP challenge.",
		}
		return
	}

	if identifier.Type != core.IdentifierDNS {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Identifier type for SimpleHTTP was not DNS",
		}
		return
	}
	hostName := identifier.Value

	var scheme string
	if input.TLS == nil || (input.TLS != nil && *input.TLS) {
		scheme = "https"
	} else {
		scheme = "http"
	}
	if va.TestMode {
		hostName = "localhost:5001"
	}

	url := fmt.Sprintf("%s://%s/.well-known/acme-challenge/%s", scheme, hostName, challenge.Path)

	// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
	va.log.Audit(fmt.Sprintf("Attempting to validate Simple%s for %s", strings.ToUpper(scheme), url))
	httpRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "URL provided for SimpleHTTP was invalid: " + err.Error(),
		}
		return
	}

	if va.UserAgent != "" {
		httpRequest.Header["User-Agent"] = []string{va.UserAgent}
	}

	httpRequest.Host = hostName
	tr := &http.Transport{
		// We are talking to a client that does not yet have a certificate,
		// so we accept a temporary, invalid one.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// We don't expect to make multiple requests to a client, so close
		// connection immediately.
		DisableKeepAlives: true,
	}
	client := http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		challenge.Error = &core.ProblemDetails{
			Type:   parseHTTPConnError(err),
			Detail: fmt.Sprintf("Could not connect to %s: %s", url, err.Error()),
		}
		return
	}
	if httpResponse.StatusCode != 200 {
		challenge.Error = &core.ProblemDetails{
			Type: core.UnauthorizedProblem,
			Detail: fmt.Sprintf("Invalid response from %s: HTTP %d",
				url, httpResponse.StatusCode),
		}
		return
	}

	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		challenge.Error = &core.ProblemDetails{
			Type: core.ServerInternalProblem,
			Detail: "Error reading HTTP response: " + err.Error(),
		}
	} else if subtle.ConstantTimeCompare(body, []byte(challenge.Token)) != 1 {
		challenge.Error = &core.ProblemDetails{
			Type: core.UnauthorizedProblem,
			Detail: fmt.Sprintf("Incorrect token validating Simple%s for %s",
				strings.ToUpper(scheme), url),
		}
	}
	return
}

func (va ValidationAuthorityImpl) validateDvsni(identifier core.AcmeIdentifier, input core.Challenge) (challenge core.Challenge) {
	challenge = input
	challenge.Error = nil
	defer va.debugValidation("DVSNI", identifier, &challenge)

	if identifier.Type != "dns" {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Identifier type for DVSNI was not DNS",
		}
		return
	}

	const DVSNIsuffix = ".acme.invalid"
	nonceName := challenge.Nonce + DVSNIsuffix

	R, err := core.B64dec(challenge.R)
	if err != nil {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Failed to decode R value from DVSNI challenge: " + err.Error(),
		}
		return
	}
	S, err := core.B64dec(challenge.S)
	if err != nil {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Failed to decode S value from DVSNI challenge: " + err.Error(),
		}
		return
	}
	RS := append(R, S...)

	z := sha256.Sum256(RS)
	zName := fmt.Sprintf("%064x.acme.invalid", z)

	// Make a connection with SNI = nonceName
	hostPort := identifier.Value + ":443"
	if va.TestMode {
		hostPort = "localhost:5001"
	}
	va.log.Notice(fmt.Sprintf("validateDVSNI: [%s] Attempting to validate DVSNI for %s %s",
		identifier, hostPort, zName))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", hostPort, &tls.Config{
		ServerName:         nonceName,
		InsecureSkipVerify: true,
	})

	if err != nil {
		challenge.Error = &core.ProblemDetails{
			Type:   parseHTTPConnError(err),
			Detail: "Failed to connect to host for DVSNI challenge: " + err.Error(),
		}
		return
	}
	defer conn.Close()

	// Check that zName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		challenge.Error = &core.ProblemDetails{
			Type:   core.UnauthorizedProblem,
			Detail: "No certs presented for DVSNI challenge",
		}
		return
	}

	for _, name := range certs[0].DNSNames {
		if subtle.ConstantTimeCompare([]byte(name), []byte(zName)) == 1 {
			return
		}
	}
	challenge.Error = &core.ProblemDetails{
		Type:   core.UnauthorizedProblem,
		Detail: "Correct zName not found for DVSNI challenge",
	}
	return
}

// parseHTTPConnError returns the ACME ProblemType corresponding to an error
// that occurred during domain validation.
func parseHTTPConnError(err error) core.ProblemType {
	if urlErr, ok := err.(*url.Error); ok {
		err = urlErr.Err
	}

	// XXX: On all of the resolvers I tested that validate DNSSEC, there is
	// no differentation between a DNSSEC failure and an unknown host. If we
	// do not verify DNSSEC ourselves, this function should be modified.
	if netErr, ok := err.(*net.OpError); ok {
		dnsErr, ok := netErr.Err.(*net.DNSError)
		if ok && !dnsErr.Timeout() && !dnsErr.Temporary() {
			return core.UnknownHostProblem
		} else if fmt.Sprintf("%T", netErr.Err) == "tls.alert" {
			return core.TLSProblem
		}
	}

	return core.ConnectionProblem
}

func (va ValidationAuthorityImpl) validateDNS(identifier core.AcmeIdentifier, input core.Challenge) (challenge core.Challenge) {
	challenge = input
	challenge.Error = nil
	defer va.debugValidation("DNS", identifier, &challenge)

	if identifier.Type != core.IdentifierDNS {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Identifier type for DNS was not itself DNS",
		}
		return
	}

	const DNSPrefix = "_acme-challenge"

	challengeSubdomain := fmt.Sprintf("%s.%s", DNSPrefix, identifier.Value)
	txts, _, err := va.DNSResolver.LookupTXT(challengeSubdomain)

	if err != nil {
		if dnssecErr, ok := err.(core.DNSSECError); ok {
			challenge.Error = &core.ProblemDetails{
				Type:   core.DNSSECProblem,
				Detail: dnssecErr.Error(),
			}
		} else {
			challenge.Error = &core.ProblemDetails{
				Type:   core.ServerInternalProblem,
				Detail: "Unable to communicate with DNS server: " + err.Error(),
			}
		}
		return
	}

	byteToken := []byte(challenge.Token)
	for _, element := range txts {
		if subtle.ConstantTimeCompare([]byte(element), byteToken) == 1 {
			return
		}
	}
	challenge.Error = &core.ProblemDetails{
		Type:   core.UnauthorizedProblem,
		Detail: "Correct value not found for DNS challenge",
	}
	return
}

// Overall validation process

func (va ValidationAuthorityImpl) validate(authz core.Authorization, challengeIndex int) {

	// Select the first supported validation method
	// XXX: Remove the "break" lines to process all supported validations
	logEvent := verificationRequestEvent{
		ID:          authz.ID,
		Requester:   authz.RegistrationID,
		RequestTime: time.Now(),
	}
	if !authz.Challenges[challengeIndex].IsSane(true) {
		chall := &authz.Challenges[challengeIndex]
		chall.Status = core.StatusInvalid
		chall.Error = &core.ProblemDetails{Type: core.MalformedProblem,
			Detail: fmt.Sprintf("Challenge failed sanity check.")}
		logEvent.Challenge = *chall
		logEvent.Error = chall.Error.Detail
	} else {
		c := authz.Challenges[challengeIndex]
		switch c.Type {
		case core.ChallengeTypeSimpleHTTP:
			c = va.validateSimpleHTTP(authz.Identifier, c)
		case core.ChallengeTypeDVSNI:
			c = va.validateDvsni(authz.Identifier, c)
		case core.ChallengeTypeDNS:
			c = va.validateDNS(authz.Identifier, c)
		}

		if c.Error != nil {
			c.Status = core.StatusInvalid
			logEvent.Error = c.Error.Error()
		} else {
			c.Status = core.StatusValid
		}
		logEvent.Challenge = c
		authz.Challenges[challengeIndex] = c
	}

	// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
	va.log.AuditObject("Validation result", logEvent)

	va.log.Notice(fmt.Sprintf("Validations: %+v", authz))

	va.RA.OnValidationUpdate(authz)
}

// UpdateValidations runs the validate() method asynchronously using goroutines.
func (va ValidationAuthorityImpl) UpdateValidations(authz core.Authorization, challengeIndex int) error {
	go va.validate(authz, challengeIndex)
	return nil
}

// CAASet consists of filtered CAA records
type CAASet struct {
	Issue     []*dns.CAA
	Issuewild []*dns.CAA
	Iodef     []*dns.CAA
	Unknown   []*dns.CAA
}

// returns true if any CAA records have unknown tag properties and are flagged critical.
func (caaSet CAASet) criticalUnknown() bool {
	if len(caaSet.Unknown) > 0 {
		for _, caaRecord := range caaSet.Unknown {
			// Critical flag is 1, but according to RFC 6844 any flag other than
			// 0 should currently be interpreted as critical.
			if caaRecord.Flag > 0 {
				return true
			}
		}
	}

	return false
}

// Filter CAA records by property
func newCAASet(CAAs []*dns.CAA) *CAASet {
	var filtered CAASet

	for _, caaRecord := range CAAs {
		switch caaRecord.Tag {
		case "issue":
			filtered.Issue = append(filtered.Issue, caaRecord)
		case "issuewild":
			filtered.Issuewild = append(filtered.Issuewild, caaRecord)
		case "iodef":
			filtered.Iodef = append(filtered.Iodef, caaRecord)
		default:
			filtered.Unknown = append(filtered.Unknown, caaRecord)
		}
	}

	return &filtered
}

func (va *ValidationAuthorityImpl) getCAASet(domain string, dnsResolver core.DNSResolver) (*CAASet, error) {
	domain = strings.TrimRight(domain, ".")
	splitDomain := strings.Split(domain, ".")
	// RFC 6844 CAA set query sequence, 'x.y.z.com' => ['x.y.z.com', 'y.z.com', 'z.com']
	for i := range splitDomain {
		queryDomain := strings.Join(splitDomain[i:], ".")
		// Don't query a public suffix
		if _, present := policy.PublicSuffixList[queryDomain]; present {
			break
		}

		// Query CAA records for domain and its alias if it has a CNAME
		for _, alias := range []bool{false, true} {
			CAAs, err := va.DNSResolver.LookupCAA(queryDomain, alias)
			if err != nil {
				return nil, err
			}

			if len(CAAs) > 0 {
				return newCAASet(CAAs), nil
			}
		}
	}

	// no CAA records found
	return nil, nil
}

// CheckCAARecords verifies that, if the indicated subscriber domain has any CAA
// records, they authorize the configured CA domain to issue a certificate
func (va *ValidationAuthorityImpl) CheckCAARecords(identifier core.AcmeIdentifier) (present, valid bool, err error) {
	domain := strings.ToLower(identifier.Value)
	caaSet, err := va.getCAASet(domain, va.DNSResolver)
	if err != nil {
		return
	}
	if caaSet == nil {
		// No CAA records found, can issue
		present = false
		valid = true
		return
	} else if caaSet.criticalUnknown() {
		present = true
		valid = false
		return
	} else if len(caaSet.Issue) > 0 || len(caaSet.Issuewild) > 0 {
		present = true
		var checkSet []*dns.CAA
		if strings.SplitN(domain, ".", 2)[0] == "*" {
			checkSet = caaSet.Issuewild
		} else {
			checkSet = caaSet.Issue
		}
		for _, caa := range checkSet {
			if caa.Value == va.IssuerDomain {
				valid = true
				return
			} else if caa.Flag > 0 {
				valid = false
				return
			}
		}

		valid = false
		return
	}

	return
}
