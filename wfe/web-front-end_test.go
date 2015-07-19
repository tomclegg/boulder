// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wfe

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/core"

	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/test"
)

const (
	agreementURL = "http://example.invalid/terms"

	test1KeyPublicJSON = `
	{
		"kty":"RSA",
		"n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
		"e":"AAEAAQ"
	}`

	test1KeyPrivatePEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyNWVhtYEKJR21y9xsHV+PD/bYwbXSeNuFal46xYxVfRL5mqh
a7vttvjB/vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K/klBYN8oYvTwwmeSkAz
6ut7ZxPv+nZaT5TJhGk0NT2kh/zSpdriEJ/3vW+mqxYbbBmpvHqsa1/zx9fSuHYc
tAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV+mzfMyboQjujPh7aNJxAWS
q4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF+w8hOTI3XXohUdu
29Se26k2B0PolDSuj0GIQU6+W9TdLXSjBb2SpQIDAQABAoIBAHw58SXYV/Yp72Cn
jjFSW+U0sqWMY7rmnP91NsBjl9zNIe3C41pagm39bTIjB2vkBNR8ZRG7pDEB/QAc
Cn9Keo094+lmTArjL407ien7Ld+koW7YS8TyKADYikZo0vAK3qOy14JfQNiFAF9r
Bw61hG5/E58cK5YwQZe+YcyBK6/erM8fLrJEyw4CV49wWdq/QqmNYU1dx4OExAkl
KMfvYXpjzpvyyTnZuS4RONfHsO8+JTyJVm+lUv2x+bTce6R4W++UhQY38HakJ0x3
XRfXooRv1Bletu5OFlpXfTSGz/5gqsfemLSr5UHncsCcFMgoFBsk2t/5BVukBgC7
PnHrAjkCgYEA887PRr7zu3OnaXKxylW5U5t4LzdMQLpslVW7cLPD4Y08Rye6fF5s
O/jK1DNFXIoUB7iS30qR7HtaOnveW6H8/kTmMv/YAhLO7PAbRPCKxxcKtniEmP1x
ADH0tF2g5uHB/zeZhCo9qJiF0QaJynvSyvSyJFmY6lLvYZsAW+C+PesCgYEA0uCi
Q8rXLzLpfH2NKlLwlJTi5JjE+xjbabgja0YySwsKzSlmvYJqdnE2Xk+FHj7TCnSK
KUzQKR7+rEk5flwEAf+aCCNh3W4+Hp9MmrdAcCn8ZsKmEW/o7oDzwiAkRCmLw/ck
RSFJZpvFoxEg15riT37EjOJ4LBZ6SwedsoGA/a8CgYEA2Ve4sdGSR73/NOKZGc23
q4/B4R2DrYRDPhEySnMGoPCeFrSU6z/lbsUIU4jtQWSaHJPu4n2AfncsZUx9WeSb
OzTCnh4zOw33R4N4W8mvfXHODAJ9+kCc1tax1YRN5uTEYzb2dLqPQtfNGxygA1DF
BkaC9CKnTeTnH3TlKgK8tUcCgYB7J1lcgh+9ntwhKinBKAL8ox8HJfkUM+YgDbwR
sEM69E3wl1c7IekPFvsLhSFXEpWpq3nsuMFw4nsVHwaGtzJYAHByhEdpTDLXK21P
heoKF1sioFbgJB1C/Ohe3OqRLDpFzhXOkawOUrbPjvdBM2Erz/r11GUeSlpNazs7
vsoYXQKBgFwFM1IHmqOf8a2wEFa/a++2y/WT7ZG9nNw1W36S3P04K4lGRNRS2Y/S
snYiqxD9nL7pVqQP2Qbqbn0yD6d3G5/7r86F7Wu2pihM8g6oyMZ3qZvvRIBvKfWo
eROL1ve1vmQF3kjrMPhhK2kr6qdWnTE5XlPllVSZFQenSTzj98AO
-----END RSA PRIVATE KEY-----
`

	test2KeyPublicJSON = `{
		"kty":"RSA",
		"n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw",
		"e":"AAEAAQ"
	}`

	test2KeyPrivatePEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqnARLrT7Xz4gRcKyLdydmCr+ey9OuPImX4X40thk3on26FkM
znR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBr
hR6uIoO4jAzJZR+ChzZuSDt7iHN+3xUVspu5XGwXU/MVJZshTwp4TaFx5elHIT/O
bnTvTOU3Xhish07AbgZKmWsVbXh5s+CrIicU4OexJPgunWZ/YJJueOKmTvnLlTV4
MzKR2oZlBKZ27S0+SfdV/QDx/ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY/2Uzi5
eX0lTc7MPRwz6qR1kip+i59VcGcUQgqHV6FyqwIDAQABAoIBAG5m8Xpj2YC0aYtG
tsxmX9812mpJFqFOmfS+f5N0gMJ2c+3F4TnKz6vE/ZMYkFnehAT0GErC4WrOiw68
F/hLdtJM74gQ0LGh9dKeJmz67bKqngcAHWW5nerVkDGIBtzuMEsNwxofDcIxrjkr
G0b7AHMRwXqrt0MI3eapTYxby7+08Yxm40mxpSsW87FSaI61LDxUDpeVkn7kolSN
WifVat7CpZb/D2BfGAQDxiU79YzgztpKhbynPdGc/OyyU+CNgk9S5MgUX2m9Elh3
aXrWh2bT2xzF+3KgZdNkJQcdIYVoGq/YRBxlGXPYcG4Do3xKhBmH79Io2BizevZv
nHkbUGECgYEAydjb4rl7wYrElDqAYpoVwKDCZAgC6o3AKSGXfPX1Jd2CXgGR5Hkl
ywP0jdSLbn2v/jgKQSAdRbYuEiP7VdroMb5M6BkBhSY619cH8etoRoLzFo1GxcE8
Y7B598VXMq8TT+TQqw/XRvM18aL3YDZ3LSsR7Gl2jF/sl6VwQAaZToUCgYEA2Cn4
fG58ME+M4IzlZLgAIJ83PlLb9ip6MeHEhUq2Dd0In89nss7Acu0IVg8ES88glJZy
4SjDLGSiuQuoQVo9UBq/E5YghdMJFp5ovwVfEaJ+ruWqOeujvWzzzPVyIWSLXRQa
N4kedtfrlqldMIXywxVru66Q1NOGvhDHm/Q8+28CgYEAkhLCbn3VNed7A9qidrkT
7OdqRoIVujEDU8DfpKtK0jBP3EA+mJ2j4Bvoq4uZrEiBSPS9VwwqovyIstAfX66g
Qv95IK6YDwfvpawUL9sxB3ZU/YkYIp0JWwun+Mtzo1ZYH4V0DZfVL59q9of9hj9k
V+fHfNOF22jAC67KYUtlPxECgYEAwF6hj4L3rDqvQYrB/p8tJdrrW+B7dhgZRNkJ
fiGd4LqLGUWHoH4UkHJXT9bvWNPMx88YDz6qapBoq8svAnHfTLFwyGp7KP1FAkcZ
Kp4KG/SDTvx+QCtvPX1/fjAUUJlc2QmxxyiU3uiK9Tpl/2/FOk2O4aiZpX1VVUIz
kZuKxasCgYBiVRkEBk2W4Ia0B7dDkr2VBrz4m23Y7B9cQLpNAapiijz/0uHrrCl8
TkLlEeVOuQfxTadw05gzKX0jKkMC4igGxvEeilYc6NR6a4nvRulG84Q8VV9Sy9Ie
wk6Oiadty3eQqSBJv0HnpmiEdQVffIK5Pg4M8Dd+aOBnEkbopAJOuA==
-----END RSA PRIVATE KEY-----
`

	// Cert generated by Go:
	// * Randomly generated key
	// * CN = lets-encrypt
	// * DNSNames = not-an-example.com
	// Used for NewCertificate tests
	GoodTestCert = "3082013e3081eba003020102020100300b06092a864886f70d01010b300030221" +
		"80f32303539313131303233303030305a180f3230353931313130323330303030" +
		"5a3000305c300d06092a864886f70d0101010500034b003048024100e5d1cc1f6" +
		"10d20913d88e5bba1f327d32450fa650c6fa8d084b710d883f3372008cf97bc41" +
		"2cb1ed3a0b28516fa839073f40b061fdb616b1b33181d28d91a5a90203010001a" +
		"34e304c301d0603551d250416301406082b0601050507030106082b0601050507" +
		"0302300c0603551d130101ff04023000301d0603551d110416301482126e6f742" +
		"d616e2d6578616d706c652e636f6d300b06092a864886f70d01010b0341008cf8" +
		"f349efa6d2fadbaf8ed9ba67e5a9b98c3d5a13c06297c4cf36dc76f494e8887e3" +
		"5dd9c885526136d810fc7640f5ba56281e2b75fa3ff7c91a7d23bab7fd4"
)

type MockSA struct {
	// empty
}

func (sa *MockSA) GetRegistration(id int64) (core.Registration, error) {
	if id == 100 {
		// Tag meaning "Missing"
		return core.Registration{}, errors.New("missing")
	}
	if id == 101 {
		// Tag meaning "Malformed"
		return core.Registration{}, nil
	}

	keyJSON := []byte(test1KeyPublicJSON)
	var parsedKey jose.JsonWebKey
	parsedKey.UnmarshalJSON(keyJSON)

	return core.Registration{ID: id, Key: parsedKey, Agreement: agreementURL}, nil
}

func (sa *MockSA) GetRegistrationByKey(jwk jose.JsonWebKey) (core.Registration, error) {
	var test1KeyPublic jose.JsonWebKey
	var test2KeyPublic jose.JsonWebKey
	test1KeyPublic.UnmarshalJSON([]byte(test1KeyPublicJSON))
	test2KeyPublic.UnmarshalJSON([]byte(test2KeyPublicJSON))

	if core.KeyDigestEquals(jwk, test1KeyPublic) {
		return core.Registration{ID: 1, Key: jwk, Agreement: agreementURL}, nil
	}

	if core.KeyDigestEquals(jwk, test2KeyPublic) {
		// No key found
		return core.Registration{ID: 2}, sql.ErrNoRows
	}

	// Return a fake registration
	return core.Registration{ID: 1, Agreement: agreementURL}, nil
}

func (sa *MockSA) GetAuthorization(id string) (core.Authorization, error) {
	if id == "valid" {
		exp := time.Now().AddDate(100, 0, 0)
		return core.Authorization{Status: core.StatusValid, RegistrationID: 1, Expires: &exp, Identifier: core.AcmeIdentifier{Type: "dns", Value: "not-an-example.com"}}, nil
	}
	return core.Authorization{}, nil
}

func (sa *MockSA) GetCertificate(serial string) (core.Certificate, error) {
	// Serial ee == 238.crt
	if serial == "000000000000000000000000000000ee" {
		certPemBytes, _ := ioutil.ReadFile("test/238.crt")
		certBlock, _ := pem.Decode(certPemBytes)
		return core.Certificate{
			RegistrationID: 1,
			DER:            certBlock.Bytes,
		}, nil
	} else if serial == "000000000000000000000000000000b2" {
		certPemBytes, _ := ioutil.ReadFile("test/178.crt")
		certBlock, _ := pem.Decode(certPemBytes)
		return core.Certificate{
			RegistrationID: 1,
			DER:            certBlock.Bytes,
		}, nil
	} else {
		return core.Certificate{}, errors.New("No cert")
	}
}

func (sa *MockSA) GetCertificateByShortSerial(string) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (sa *MockSA) GetCertificateStatus(serial string) (core.CertificateStatus, error) {
	// Serial ee == 238.crt
	if serial == "000000000000000000000000000000ee" {
		return core.CertificateStatus{
			Status: core.OCSPStatusGood,
		}, nil
	} else if serial == "000000000000000000000000000000b2" {
		return core.CertificateStatus{
			Status: core.OCSPStatusRevoked,
		}, nil
	} else {
		return core.CertificateStatus{}, errors.New("No cert status")
	}
}

func (sa *MockSA) AlreadyDeniedCSR([]string) (bool, error) {
	return false, nil
}

func (sa *MockSA) AddCertificate(certDER []byte, regID int64) (digest string, err error) {
	return
}

func (sa *MockSA) FinalizeAuthorization(authz core.Authorization) (err error) {
	return
}

func (sa *MockSA) MarkCertificateRevoked(serial string, ocspResponse []byte, reasonCode int) (err error) {
	return
}

func (sa *MockSA) UpdateOCSP(serial string, ocspResponse []byte) (err error) {
	return
}

func (sa *MockSA) NewPendingAuthorization(authz core.Authorization) (output core.Authorization, err error) {
	return
}

func (sa *MockSA) NewRegistration(reg core.Registration) (regR core.Registration, err error) {
	return
}

func (sa *MockSA) UpdatePendingAuthorization(authz core.Authorization) (err error) {
	return
}

func (sa *MockSA) UpdateRegistration(reg core.Registration) (err error) {
	return
}

type MockRegistrationAuthority struct{}

func (ra *MockRegistrationAuthority) NewRegistration(reg core.Registration) (core.Registration, error) {
	return reg, nil
}

func (ra *MockRegistrationAuthority) NewAuthorization(authz core.Authorization, regID int64) (core.Authorization, error) {
	authz.RegistrationID = regID
	authz.ID = "bkrPh2u0JUf18-rVBZtOOWWb3GuIiliypL-hBM9Ak1Q"
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
	return nil
}

type MockCA struct{}

func (ca *MockCA) IssueCertificate(csr x509.CertificateRequest, regID int64, earliestExpiry time.Time) (cert core.Certificate, err error) {
	// Return a basic certificate so NewCertificate can continue
	randomCertDer, _ := hex.DecodeString(GoodTestCert)
	cert.DER = randomCertDer
	return
}

func (ca *MockCA) GenerateOCSP(xferObj core.OCSPSigningRequest) (ocsp []byte, err error) {
	return
}

func (ca *MockCA) RevokeCertificate(serial string, reasonCode int) (err error) {
	return
}

func makeBody(s string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(s))
}

func signRequest(t *testing.T, req string, nonceService *core.NonceService) string {
	accountKeyJSON := []byte(`{"kty":"RSA","n":"z2NsNdHeqAiGdPP8KuxfQXat_uatOK9y12SyGpfKw1sfkizBIsNxERjNDke6Wp9MugN9srN3sr2TDkmQ-gK8lfWo0v1uG_QgzJb1vBdf_hH7aejgETRGLNJZOdaKDsyFnWq1WGJq36zsHcd0qhggTk6zVwqczSxdiWIAZzEakIUZ13KxXvoepYLY0Q-rEEQiuX71e4hvhfeJ4l7m_B-awn22UUVvo3kCqmaRlZT-36vmQhDGoBsoUo1KBEU44jfeK5PbNRk7vDJuH0B7qinr_jczHcvyD-2TtPzKaCioMtNh_VZbPNDaG67sYkQlC15-Ff3HPzKKJW2XvkVG91qMvQ","e":"AAEAAQ","d":"BhAmDbzBAbCeHbU0Xhzi_Ar4M0eTMOEQPnPXMSfW6bc0SRW938JO_-z1scEvFY8qsxV_C0Zr7XHVZsmHz4dc9BVmhiSan36XpuOS85jLWaY073e7dUVN9-l-ak53Ys9f6KZB_v-BmGB51rUKGB70ctWiMJ1C0EzHv0h6Moog-LCd_zo03uuZD5F5wtnPrAB3SEM3vRKeZHzm5eiGxNUsaCEzGDApMYgt6YkQuUlkJwD8Ky2CkAE6lLQSPwddAfPDhsCug-12SkSIKw1EepSHz86ZVfJEnvY-h9jHIdI57mR1v7NTCDcWqy6c6qIzxwh8n2X94QTbtWT3vGQ6HXM5AQ","p":"2uhvZwNS5i-PzeI9vGx89XbdsVmeNjVxjH08V3aRBVY0dzUzwVDYk3z7sqBIj6de53Lx6W1hjmhPIqAwqQgjIKH5Z3uUCinGguKkfGDL3KgLCzYL2UIvZMvTzr9NWLc0AHMZdee5utxWKCGnZBOqy1Rd4V-6QrqjEDBvanoqA60","q":"8odNkMEiriaDKmvwDv-vOOu3LaWbu03yB7VhABu-hK5Xx74bHcvDP2HuCwDGGJY2H-xKdMdUPs0HPwbfHMUicD2vIEUDj6uyrMMZHtbcZ3moh3-WESg3TaEaJ6vhwcWXWG7Wc46G-HbCChkuVenFYYkoi68BAAjloqEUl1JBT1E"}`)
	var accountKey jose.JsonWebKey
	err := json.Unmarshal(accountKeyJSON, &accountKey)
	test.AssertNotError(t, err, "Failed to unmarshal key")
	signer, err := jose.NewSigner("RS256", &accountKey)
	test.AssertNotError(t, err, "Failed to make signer")
	nonce, err := nonceService.Nonce()
	test.AssertNotError(t, err, "Failed to make nonce")
	result, err := signer.Sign([]byte(req), nonce)
	test.AssertNotError(t, err, "Failed to sign req")
	ret := result.FullSerialize()
	return ret
}

func setupWFE(t *testing.T) WebFrontEndImpl {
	wfe, err := NewWebFrontEndImpl()
	test.AssertNotError(t, err, "Unable to create WFE")

	wfe.NewReg = wfe.BaseURL + NewRegPath
	wfe.RegBase = wfe.BaseURL + RegPath
	wfe.NewAuthz = wfe.BaseURL + NewAuthzPath
	wfe.AuthzBase = wfe.BaseURL + AuthzPath
	wfe.NewCert = wfe.BaseURL + NewCertPath
	wfe.CertBase = wfe.BaseURL + CertPath
	wfe.SubscriberAgreementURL = agreementURL

	return wfe
}

func mustParseURL(s string) *url.URL {
	if u, err := url.Parse(s); err != nil {
		panic("Cannot parse URL " + s)
	} else {
		return u
	}
}

func TestStandardHeaders(t *testing.T) {
	wfe := setupWFE(t)

	cases := []struct {
		path    string
		handler func(http.ResponseWriter, *http.Request)
		allowed []string
	}{
		{"/", wfe.Index, []string{"GET"}},
		{wfe.NewReg, wfe.NewRegistration, []string{"POST"}},
		{wfe.RegBase, wfe.Registration, []string{"POST"}},
		{wfe.NewAuthz, wfe.NewAuthorization, []string{"POST"}},
		{wfe.AuthzBase, wfe.Authorization, []string{"GET", "POST"}},
		{wfe.NewCert, wfe.NewCertificate, []string{"POST"}},
		{wfe.CertBase, wfe.Certificate, []string{"GET", "POST"}},
		{wfe.SubscriberAgreementURL, wfe.Terms, []string{"GET"}},
	}

	for _, c := range cases {
		responseWriter := httptest.NewRecorder()
		url, _ := url.Parse(c.path)
		c.handler(responseWriter, &http.Request{
			Method: "BOGUS",
			URL:    url,
		})
		acao := responseWriter.Header().Get("Access-Control-Allow-Origin")
		nonce := responseWriter.Header().Get("Replay-Nonce")
		allow := responseWriter.Header().Get("Allow")
		test.Assert(t, responseWriter.Code == http.StatusMethodNotAllowed, "Bogus method allowed")
		test.Assert(t, acao == "*", "Bad CORS header")
		test.Assert(t, len(nonce) > 0, "Bad Replay-Nonce header")
		test.Assert(t, len(allow) > 0 && allow == strings.Join(c.allowed, ", "), "Bad Allow header")
	}
}

func TestIndex(t *testing.T) {
	wfe := setupWFE(t)

	responseWriter := httptest.NewRecorder()

	url, _ := url.Parse("/")
	wfe.Index(responseWriter, &http.Request{
		Method: "GET",
		URL:    url,
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertNotEquals(t, responseWriter.Body.String(), "404 page not found\n")
	test.Assert(t, strings.Contains(responseWriter.Body.String(), wfe.NewReg),
		"new-reg not found")

	responseWriter.Body.Reset()
	url, _ = url.Parse("/foo")
	wfe.Index(responseWriter, &http.Request{
		URL: url,
	})
	//test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
	test.AssertEquals(t, responseWriter.Body.String(), "404 page not found\n")
}

// TODO: Write additional test cases for:
//  - RA returns with a failure
func TestIssueCertificate(t *testing.T) {
	wfe := setupWFE(t)
	mux := wfe.Handler()

	// TODO: Use a mock RA so we can test various conditions of authorized, not authorized, etc.
	ra := ra.NewRegistrationAuthorityImpl()
	ra.SA = &MockSA{}
	ra.CA = &MockCA{}
	wfe.SA = &MockSA{}
	wfe.RA = &ra
	wfe.Stats, _ = statsd.NewNoopClient()
	responseWriter := httptest.NewRecorder()

	newCertURL := mustParseURL(NewCertPath)

	// GET instead of POST should be rejected
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    newCertURL,
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Method not allowed\"}")

	// POST, but no body.
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newCertURL,
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Unable to read/verify body\"}")

	// POST, but body that isn't valid JWS
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newCertURL,
		Body:   makeBody("hi"),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Unable to read/verify body\"}")

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newCertURL,
		Body:   makeBody(signRequest(t, "foo", &wfe.nonceService)),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Error unmarshaling certificate request\"}")

	// Valid, signed JWS body, payload is '{}'
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newCertURL,
		Body:   makeBody(signRequest(t, "{}", &wfe.nonceService)),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Error unmarshaling certificate request\"}")

	// Valid, signed JWS body, payload has a invalid signature on CSR and no authorizations:
	// {
	//   "csr": "MIICU...",
	//   "authorizations: []
	// }
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newCertURL,
		Body: makeBody(signRequest(t, `{
      "csr": "MIICUzCCATsCAQAwDjEMMAoGA1UEAwwDZm9vMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3UWce2PY9y8n4B7jOk3DXZnu2pUgLqs7a5DzRBxnPqL7axis6thjSBI2FO7w5CUjO-m8XjD-GYWgfXebZ3aQVlBiYqdxZ3UG6RDwEbBCeKo7v8W-UUfESNNCXF874ddhJmEw0RF0YWSAEctAYHEGoPFz69gCql6xXDPY1OlpMArkIIlq9EZWwT081ekyJv0GYRfQigCMK4b1gkFvKsHja9-Q5u1b0AZyA-mPTu6z5EWkB2onhAXwWXX90sfUe8DSet9r9GxMln3lgZWT1zh3RMZILp0Uhh3NbXnA8JInukha3HPO8WgmDd4K6uBzWso0A6fp5NpX28ZpKAwM5iQltQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAFGJV3OcghJEZvO_hGtIdaRnsu6eX3CeqS0bYcEEza8vizlj4x09ntMH3QooqPOj8suul0vD75HZTpz6FHE7SyLeNKQBGNGp1PMWmXsFqD6xURCyMHvCZoHynpCr7D5HtzIvu9fAV7XRK7qBKXfRxbv21q0ysMWnfwkbS2wrs1wAzPPg4iGJq8uVItrlcFL8buJLzxvKa3lu_OjxNXjzdEt3VVko-AKS1swkYEhsGwKd8ZzNbpF2IQ-okXgR_ZecyW8t83pV-w33GhDL9w6RLRMgSM5aojy8ri7YIoIvc3-9klbw2kwY5oM2lmhoIOGU10TkEyn18myy_5GUEGhNzPA=",
      "authorizations": []
    }`, &wfe.nonceService)),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:unauthorized\",\"detail\":\"Error creating new cert :: Invalid signature on CSR\"}")

	// Valid, signed JWS body, payload has a CSR with no DNS names
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newCertURL,
		Body: makeBody(signRequest(t, `{
      "authorizations": [],
      "csr": "MIIBBTCBsgIBADBNMQowCAYDVQQGEwFjMQowCAYDVQQKEwFvMQswCQYDVQQLEwJvdTEKMAgGA1UEBxMBbDEKMAgGA1UECBMBczEOMAwGA1UEAxMFT2ggaGkwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAsr76ZkU2RTqi41eHfmpE5htDvkr202yjRS8x2M5yzT52ooT2WEVtnSuim0YfOEw6f-fHmbqsasqKmqlsJdgz2QIDAQABoAAwCwYJKoZIhvcNAQEFA0EAHkCv4kVPJa53ltOGrhpdH0mT04qHUqiTllJPPjxXxn6iwiVYL8nQuhs4Q2758ENoODBuM2F8gH19TIoXlcm3LQ=="
    }`, &wfe.nonceService)),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:unauthorized\",\"detail\":\"Error creating new cert :: Key not authorized for name Oh hi\"}")

	// Valid, signed JWS body, payload has a valid CSR but no authorizations:
	// {
	//   "csr": "MIIBK...",
	//   "authorizations: []
	// }
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newCertURL,
		Body: makeBody(signRequest(t, `{
      "authorizations": [],
      "csr": "MIIBKzCB2AIBADBNMQowCAYDVQQGEwFjMQowCAYDVQQKEwFvMQswCQYDVQQLEwJvdTEKMAgGA1UEBxMBbDEKMAgGA1UECBMBczEOMAwGA1UEAxMFT2ggaGkwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAqvFEGBNrjAotPbcdTSyDpxsESN0-eYl4TqS0ZLYwLTV-FuPHTPjFiq2oH1BEgmRzjb8YiPVXFMnaOeHE7zuuXQIDAQABoCYwJAYJKoZIhvcNAQkOMRcwFTATBgNVHREEDDAKgghtZWVwLmNvbTALBgkqhkiG9w0BAQUDQQBSEcEq-lMUnzv1DO8jK0hJR8YKc0yV8zuWVfAWN0_dsPg5Ny-OHhtJcOTIrUrLTb_xCU7cjiKxU8i3j1kaT-rt"
    }`, &wfe.nonceService)),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:unauthorized\",\"detail\":\"Error creating new cert :: Key not authorized for name meep.com\"}")

	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newCertURL,
		Body: makeBody(signRequest(t, `{
      "csr": "MIH1MIGiAgEAMA0xCzAJBgNVBAYTAlVTMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOXRzB9hDSCRPYjlu6HzJ9MkUPplDG-o0IS3ENiD8zcgCM-XvEEsse06CyhRb6g5Bz9AsGH9thaxszGB0o2RpakCAwEAAaAwMC4GCSqGSIb3DQEJDjEhMB8wHQYDVR0RBBYwFIISbm90LWFuLWV4YW1wbGUuY29tMAsGCSqGSIb3DQEBCwNBAFpyURFqjVn-7zx73GKaBvPF_2RhBsdehqSjaJ0BpvPKmzpoIFADjttNzKkWaRRDrTeT-GGMV2Gky8S-E_dzoms=",
      "authorizations": ["valid"]
    }`, &wfe.nonceService)),
	})
	randomCertDer, _ := hex.DecodeString(GoodTestCert)
	test.AssertEquals(t,
		responseWriter.Body.String(),
		string(randomCertDer))
	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"/acme/cert/0000000000000000")
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		"</acme/issuer-cert>;rel=\"up\"")
	test.AssertEquals(
		t, responseWriter.Header().Get("Content-Type"),
		"application/pkix-cert")
}

func TestChallenge(t *testing.T) {
	wfe := setupWFE(t)

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &MockSA{}
	responseWriter := httptest.NewRecorder()

	var key jose.JsonWebKey
	err := json.Unmarshal([]byte(`
		{
			"e": "AQAB",
			"kty": "RSA",
			"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
		}
	`), &key)
	test.AssertNotError(t, err, "Could not unmarshal testing key")

	challengeURL, _ := url.Parse("/acme/authz/asdf?challenge=foo")
	authz := core.Authorization{
		ID: "asdf",
		Identifier: core.AcmeIdentifier{
			Type:  "dns",
			Value: "letsencrypt.org",
		},
		Challenges: []core.Challenge{
			core.Challenge{
				Type: "dns",
				URI:  core.AcmeURL(*challengeURL),
			},
		},
		RegistrationID: 1,
	}

	wfe.challenge(authz, responseWriter, &http.Request{
		Method: "POST",
		URL:    challengeURL,
		Body:   makeBody(signRequest(t, "{}", &wfe.nonceService)),
	}, requestEvent{})

	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"/acme/authz/asdf?challenge=foo")
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		"</acme/authz/asdf>;rel=\"up\"")
	test.AssertEquals(
		t, responseWriter.Body.String(),
		"{\"type\":\"dns\",\"uri\":\"/acme/authz/asdf?challenge=foo\"}")
}

func TestNewRegistration(t *testing.T) {
	wfe := setupWFE(t)
	mux := wfe.Handler()

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	wfe.SubscriberAgreementURL = agreementURL
	responseWriter := httptest.NewRecorder()

	newRegURL := mustParseURL(NewRegPath)

	// GET instead of POST should be rejected
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    newRegURL,
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Method not allowed\"}")

	// POST, but no body.
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newRegURL,
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Unable to read/verify body\"}")

	// POST, but body that isn't valid JWS
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newRegURL,
		Body:   makeBody("hi"),
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Unable to read/verify body\"}")

	key, err := jose.LoadPrivateKey([]byte(test2KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err := jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	responseWriter.Body.Reset()
	nonce, err := wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err := signer.Sign([]byte("foo"), nonce)
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newRegURL,
		Body:   makeBody(result.FullSerialize()),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Error unmarshaling JSON\"}")

	// Same signed body, but payload modified by one byte, breaking signature.
	// should fail JWS verification.
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newRegURL,
		Body: makeBody(`
			{
				"header": {
					"alg": "RS256",
					"jwk": {
						"e": "AQAB",
						"kty": "RSA",
						"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw"
					}
				},
				"payload": "xm9vCg",
				"signature": "RjUQ679fxJgeAJlxqgvDP_sfGZnJ-1RgWF2qmcbnBWljs6h1qp63pLnJOl13u81bP_bCSjaWkelGG8Ymx_X-aQ"
			}
    	`),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Unable to read/verify body\"}")

	responseWriter.Body.Reset()
	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err = signer.Sign(
		[]byte("{\"contact\":[\"tel:123456789\"],\"agreement\":\"https://letsencrypt.org/im-bad\"}"),
		nonce)
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newRegURL,
		Body:   makeBody(result.FullSerialize()),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Provided agreement URL [https://letsencrypt.org/im-bad] does not match current agreement URL ["+agreementURL+"]\"}")

	responseWriter.Body.Reset()
	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err = signer.Sign([]byte("{\"contact\":[\"tel:123456789\"],\"agreement\":\""+agreementURL+"\"}"), nonce)
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newRegURL,
		Body:   makeBody(result.FullSerialize()),
	})

	test.AssertEquals(t, responseWriter.Body.String(), `{"id":0,"key":{"kty":"RSA","n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw","e":"AAEAAQ"},"recoveryToken":"","contact":["tel:123456789"],"agreement":"http://example.invalid/terms"}`)
	var reg core.Registration
	err = json.Unmarshal([]byte(responseWriter.Body.String()), &reg)
	test.AssertNotError(t, err, "Couldn't unmarshal returned registration object")
	test.Assert(t, len(reg.Contact) >= 1, "No contact field in registration")
	uu := url.URL(reg.Contact[0])
	test.AssertEquals(t, uu.String(), "tel:123456789")

	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"/acme/reg/0")
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		"</acme/new-authz>;rel=\"next\"")

	key, err = jose.LoadPrivateKey([]byte(test1KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok = key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err = jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")

	// Reset the body and status code
	responseWriter = httptest.NewRecorder()
	// POST, Valid JSON, Key already in use
	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err = signer.Sign([]byte("{\"contact\":[\"tel:123456789\"],\"agreement\":\""+agreementURL+"\"}"), nonce)
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newRegURL,
		Body:   makeBody(result.FullSerialize()),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Registration key is already in use\"}")
	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"/acme/reg/1")
	test.AssertEquals(t, responseWriter.Code, 409)
}

// Valid revocation request for existing, non-revoked cert
func TestRevokeCertificate(t *testing.T) {
	keyPemBytes, err := ioutil.ReadFile("test/238.key")
	test.AssertNotError(t, err, "Failed to load key")
	key, err := jose.LoadPrivateKey(keyPemBytes)
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err := jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")

	certPemBytes, err := ioutil.ReadFile("test/238.crt")
	test.AssertNotError(t, err, "Failed to load cert")
	certBlock, _ := pem.Decode(certPemBytes)
	test.Assert(t, certBlock != nil, "Failed to decode PEM")
	var revokeRequest struct {
		CertificateDER core.JSONBuffer `json:"certificate"`
	}
	revokeRequest.CertificateDER = certBlock.Bytes
	revokeRequestJSON, err := json.Marshal(revokeRequest)
	test.AssertNotError(t, err, "Failed to marshal request")

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	wfe := setupWFE(t)
	mux := wfe.Handler()
	revokeURL := mustParseURL(RevokeCertPath)

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	wfe.SubscriberAgreementURL = agreementURL
	responseWriter := httptest.NewRecorder()
	responseWriter.Body.Reset()
	nonce, err := wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, _ := signer.Sign(revokeRequestJSON, nonce)
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    revokeURL,
		Body:   makeBody(result.FullSerialize()),
	})
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")

	// Try the revoke request again, signed by account key associated with cert.
	// Should also succeed.
	responseWriter.Body.Reset()
	test1JWK, err := jose.LoadPrivateKey([]byte(test1KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	test1Key, ok := test1JWK.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	accountKeySigner, err := jose.NewSigner("RS256", test1Key)
	test.AssertNotError(t, err, "Failed to make signer")
	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, _ = accountKeySigner.Sign(revokeRequestJSON, nonce)
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    revokeURL,
		Body:   makeBody(result.FullSerialize()),
	})
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
}

// Valid revocation request for already-revoked cert
func TestRevokeCertificateAlreadyRevoked(t *testing.T) {
	keyPemBytes, err := ioutil.ReadFile("test/178.key")
	test.AssertNotError(t, err, "Failed to load key")
	key, err := jose.LoadPrivateKey(keyPemBytes)
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err := jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")

	certPemBytes, err := ioutil.ReadFile("test/178.crt")
	test.AssertNotError(t, err, "Failed to load cert")
	certBlock, _ := pem.Decode(certPemBytes)
	test.Assert(t, certBlock != nil, "Failed to decode PEM")
	var revokeRequest struct {
		CertificateDER core.JSONBuffer `json:"certificate"`
	}
	revokeRequest.CertificateDER = certBlock.Bytes
	revokeRequestJSON, err := json.Marshal(revokeRequest)
	test.AssertNotError(t, err, "Failed to marshal request")

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	wfe := setupWFE(t)
	mux := wfe.Handler()
	revokeURL := mustParseURL(RevokeCertPath)

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	wfe.SubscriberAgreementURL = agreementURL
	responseWriter := httptest.NewRecorder()
	responseWriter.Body.Reset()
	nonce, err := wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, _ := signer.Sign(revokeRequestJSON, nonce)
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    revokeURL,
		Body:   makeBody(result.FullSerialize()),
	})
	test.AssertEquals(t, responseWriter.Code, 409)
	test.AssertEquals(t, responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Certificate already revoked\"}")
}

func TestAuthorization(t *testing.T) {
	wfe := setupWFE(t)
	mux := wfe.Handler()
	newAuthURL := mustParseURL(NewAuthzPath)

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	responseWriter := httptest.NewRecorder()

	// GET instead of POST should be rejected
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    newAuthURL,
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Method not allowed\"}")

	// POST, but no body.
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newAuthURL,
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Unable to read/verify body\"}")

	// POST, but body that isn't valid JWS
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newAuthURL,
		Body:   makeBody("hi"),
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Unable to read/verify body\"}")

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newAuthURL,
		Body:   makeBody(signRequest(t, "foo", &wfe.nonceService)),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Error unmarshaling JSON\"}")

	// Same signed body, but payload modified by one byte, breaking signature.
	// should fail JWS verification.
	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newAuthURL,
		Body: makeBody(`
			{
					"header": {
							"alg": "RS256",
							"jwk": {
									"e": "AQAB",
									"kty": "RSA",
									"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw"
							}
					},
					"payload": "xm9vCg",
					"signature": "RjUQ679fxJgeAJlxqgvDP_sfGZnJ-1RgWF2qmcbnBWljs6h1qp63pLnJOl13u81bP_bCSjaWkelGG8Ymx_X-aQ"
			}
    	`),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Unable to read/verify body\"}")

	responseWriter.Body.Reset()
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    newAuthURL,
		Body:   makeBody(signRequest(t, "{\"identifier\":{\"type\":\"dns\",\"value\":\"test.com\"}}", &wfe.nonceService)),
	})

	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"/acme/authz/bkrPh2u0JUf18-rVBZtOOWWb3GuIiliypL-hBM9Ak1Q")
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		"</acme/new-cert>;rel=\"next\"")

	test.AssertEquals(t, responseWriter.Body.String(), "{\"identifier\":{\"type\":\"dns\",\"value\":\"test.com\"}}")

	var authz core.Authorization
	err := json.Unmarshal([]byte(responseWriter.Body.String()), &authz)
	test.AssertNotError(t, err, "Couldn't unmarshal returned authorization object")
}

func TestRegistration(t *testing.T) {
	wfe := setupWFE(t)
	mux := wfe.Handler()
	regURL := mustParseURL(RegPath)

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	wfe.SubscriberAgreementURL = agreementURL
	responseWriter := httptest.NewRecorder()

	// Test invalid method
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "MAKE-COFFEE",
		URL:    regURL,
		Body:   makeBody("invalid"),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Method not allowed\"}")
	responseWriter.Body.Reset()

	// Test GET proper entry returns 405
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    regURL,
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Method not allowed\"}")
	responseWriter.Body.Reset()

	// Test POST invalid JSON
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    regURL,
		Body:   makeBody("invalid"),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Unable to read/verify body\"}")
	responseWriter.Body.Reset()

	key, err := jose.LoadPrivateKey([]byte(test2KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err := jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")

	// Test POST valid JSON but key is not registered
	nonce, err := wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err := signer.Sign([]byte("{\"agreement\":\""+agreementURL+"\"}"), nonce)
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    regURL,
		Body:   makeBody(result.FullSerialize()),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:unauthorized\",\"detail\":\"No registration exists matching provided key\"}")
	responseWriter.Body.Reset()

	key, err = jose.LoadPrivateKey([]byte(test1KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok = key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err = jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")

	// Test POST valid JSON with registration up in the mock (with incorrect agreement URL)
	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err = signer.Sign([]byte("{\"agreement\":\"https://letsencrypt.org/im-bad\"}"), nonce)

	// Test POST valid JSON with registration up in the mock
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    mustParseURL(RegPath + "1"),
		Body:   makeBody(result.FullSerialize()),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"type\":\"urn:acme:error:malformed\",\"detail\":\"Provided agreement URL [https://letsencrypt.org/im-bad] does not match current agreement URL ["+agreementURL+"]\"}")
	responseWriter.Body.Reset()

	// Test POST valid JSON with registration up in the mock (with correct agreement URL)
	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err = signer.Sign([]byte("{\"agreement\":\""+agreementURL+"\"}"), nonce)
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "POST",
		URL:    mustParseURL(RegPath + "1"),
		Body:   makeBody(result.FullSerialize()),
	})
	test.AssertNotContains(t, responseWriter.Body.String(), "urn:acme:error")
	responseWriter.Body.Reset()
}

func TestTermsRedirect(t *testing.T) {
	wfe := setupWFE(t)
	mux := wfe.Handler()

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	wfe.SubscriberAgreementURL = agreementURL

	responseWriter := httptest.NewRecorder()

	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL("/terms"),
	})
	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		agreementURL)
	test.AssertEquals(t, responseWriter.Code, 302)
}
