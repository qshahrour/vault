package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
	"gotest.tools/assert"
)

func TestCertificatesEqualOrInitial(t *testing.T) {
	type testCase struct {
		certs         []*x509.Certificate
		expectedEqual bool
		expectedCert  *x509.Certificate
	}

	opts := cli.Options{}
	pathA := "../../../testoutput/cert.pem_a"
	pathB := "../../../testoutput/cert.pem_b"
	createTestCert(pathA, "VaultBot.Test", []net.IP{net.ParseIP("127.0.0.1")}, []string{"testing.test", "helloworld.com", "VaultBot.Test"}, time.Now().Add(1*time.Hour))
	createTestCert(pathB, "VaultBot.Other", []net.IP{net.ParseIP("127.0.0.1")}, []string{"testing.test", "helloworld.com", "VaultBot.Ot"}, time.Now().Add(1*time.Hour))

	opts.PKI.CertPath = pathA
	pemFileUpdater := PEMFile{}
	a := pemFileUpdater.ReadCertificate(opts)

	opts.PKI.CertPath = pathB
	b := pemFileUpdater.ReadCertificate(opts)

	testCases := []testCase{
		{certs: []*x509.Certificate{nil, nil}, expectedEqual: true, expectedCert: nil},
		{certs: []*x509.Certificate{nil, a}, expectedEqual: true, expectedCert: a},
		{certs: []*x509.Certificate{nil, b}, expectedEqual: true, expectedCert: b},
		{certs: []*x509.Certificate{a, nil}, expectedEqual: true, expectedCert: a},
		{certs: []*x509.Certificate{a, a}, expectedEqual: true, expectedCert: a},
		{certs: []*x509.Certificate{a, b}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{b, nil}, expectedEqual: true, expectedCert: b},
		{certs: []*x509.Certificate{b, a}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{b, b}, expectedEqual: true, expectedCert: b},

		{certs: []*x509.Certificate{nil, nil, nil}, expectedEqual: true, expectedCert: nil},
		{certs: []*x509.Certificate{nil, nil, a}, expectedEqual: true, expectedCert: a},
		{certs: []*x509.Certificate{nil, nil, b}, expectedEqual: true, expectedCert: b},
		{certs: []*x509.Certificate{nil, a, nil}, expectedEqual: true, expectedCert: a},
		{certs: []*x509.Certificate{nil, a, a}, expectedEqual: true, expectedCert: a},
		{certs: []*x509.Certificate{nil, a, b}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{nil, b, nil}, expectedEqual: true, expectedCert: b},
		{certs: []*x509.Certificate{nil, b, a}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{nil, b, b}, expectedEqual: true, expectedCert: b},
		{certs: []*x509.Certificate{a, nil, nil}, expectedEqual: true, expectedCert: a},
		{certs: []*x509.Certificate{a, nil, a}, expectedEqual: true, expectedCert: a},
		{certs: []*x509.Certificate{a, nil, b}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{a, a, nil}, expectedEqual: true, expectedCert: a},
		{certs: []*x509.Certificate{a, a, a}, expectedEqual: true, expectedCert: a},
		{certs: []*x509.Certificate{a, a, b}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{a, b, nil}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{a, b, a}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{a, b, b}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{b, nil, nil}, expectedEqual: true, expectedCert: b},
		{certs: []*x509.Certificate{b, nil, a}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{b, nil, b}, expectedEqual: true, expectedCert: b},
		{certs: []*x509.Certificate{b, a, nil}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{b, a, a}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{b, a, b}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{b, b, nil}, expectedEqual: true, expectedCert: b},
		{certs: []*x509.Certificate{b, b, a}, expectedEqual: false, expectedCert: nil},
		{certs: []*x509.Certificate{b, b, b}, expectedEqual: true, expectedCert: b},
	}

	for i, c := range testCases {
		t.Logf("Running TestCertificatesEqualOrInitial Case #%d", i)
		actualEQ, actualCert := certificatesEqualOrInitial(c.certs...)
		assert.Equal(t, actualEQ, c.expectedEqual)
		assert.Equal(t, actualCert, c.expectedCert)
	}
}

// creates a test certificate with specified options
func createTestCert(path string, commonName string, ipSANs []net.IP, dnsSANs []string, notAfter time.Time) {
	RSAPrivateKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: new(big.Int).Lsh(big.NewInt(1), 128),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Acme Co"},
		},
		IsCA:                  true,
		IPAddresses:           ipSANs,
		DNSNames:              dnsSANs,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &RSAPrivateKey.PublicKey, RSAPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certOut, err := os.Create(path)
	if err != nil {
		log.Fatalf("failed to open %s for writing: %s", path, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()
}

func TestHasCertificateDataChanged(t *testing.T) {
	opts := cli.Options{}
	opts.PKI.CertPath = "../../../testoutput/cert.pem"
	createTestCert(opts.PKI.CertPath, "VaultBot.Test", []net.IP{net.ParseIP("127.0.0.1")}, []string{"testing.test", "helloworld.com", "VaultBot.Test"}, time.Now().Add(1*time.Hour))

	pemUpdater := PEMFile{}
	readCert := pemUpdater.ReadCertificate(opts)

	// nothing changed, match created cert
	opts.PKI.CommonName = "VaultBot.Test"
	opts.PKI.IPSans = "127.0.0.1"
	opts.PKI.AltNames = "testing.test,helloworld.com"

	changed := HasCertificateDataChanged(readCert, opts)
	if changed {
		t.Fatal("Certificate data changed, when it shouldnt!")
	}

	// IP SANs len changed, does not match created cert
	opts.PKI.IPSans = "127.0.0.1,192.168.0.1"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("IP SANs len did not changed, when it should!")
	}

	// IP SANs fields changed, does not match created cert
	opts.PKI.IPSans = "192.168.0.1"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("IP SANs field did not changed, when it should!")
	}

	// dns alt names len changed, does not match created cert
	opts.PKI.AltNames = "helloworld.com"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Dns alt names len did not changed, when it should!")
	}

	// dns alt names fields changed, does not match created cert
	opts.PKI.AltNames = "helloworld.com,changed.com"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Dns alt names field did not changed, when it should!")
	}

	// common name changed, does not match created cert
	opts.PKI.AltNames = "testing.test,helloworld.com"
	opts.PKI.CommonName = "VaultBot.Changed"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Certificate data did not change, when it should!")
	}
}

func TestHasCertificateDataChangedNoSans(t *testing.T) {
	opts := cli.Options{}
	opts.PKI.CertPath = "../../../testoutput/cert.pem"
	createTestCert(opts.PKI.CertPath, "VaultBot.Test", []net.IP{}, []string{"VaultBot.Test"}, time.Now().Add(1*time.Hour))

	pemUpdater := PEMFile{}
	readCert := pemUpdater.ReadCertificate(opts)

	// nothing changed, match created cert
	opts.PKI.CommonName = "VaultBot.Test"
	opts.PKI.IPSans = ""
	opts.PKI.AltNames = ""

	changed := HasCertificateDataChanged(readCert, opts)
	if changed {
		t.Fatal("Certificate data changed, when it shouldnt!")
	}

	// IP SANs len changed, does not match created cert
	opts.PKI.IPSans = "127.0.0.1,192.168.0.1"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("IP SANs len did not changed, when it should!")
	}

	// IP SANs fields changed, does not match created cert
	opts.PKI.IPSans = "192.168.0.1"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("IP SANs field did not changed, when it should!")
	}

	// dns alt names len changed, does not match created cert
	opts.PKI.AltNames = "helloworld.com"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Dns alt names len did not changed, when it should!")
	}

	// dns alt names fields changed, does not match created cert
	opts.PKI.AltNames = "helloworld.com,changed.com"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Dns alt names field did changed, when it should!")
	}

	// common name changed, does not match created cert
	opts.PKI.AltNames = "testing.test,helloworld.com"
	opts.PKI.CommonName = "VaultBot.Changed"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Certificate data did not change, when it should!")
	}
}

func TestCertificateRenewalDue(t *testing.T) {
	opts := cli.Options{}
	opts.PKI.CertPath = "../../../testoutput/cert.pem"
	createTestCert(opts.PKI.CertPath, "VaultBot.Test", []net.IP{net.ParseIP("127.0.0.1")}, []string{"testing.test"}, time.Now().Add(1*time.Hour))

	// test certificate reading
	pemUpdater := PEMFile{}
	readCert := pemUpdater.ReadCertificate(opts)

	if readCert == nil {
		t.Fatalf("Failed reading test certificate")
	}
	log.Println(readCert.Subject.CommonName)

	// test certificate expiry check
	// not yet due
	opts.PKI.RenewTime = "1m"
	if IsCertificateRenewalDue(readCert, opts) {
		t.Fatalf("Certificate expiry check failed. Marked as due for renewal when it should not!")
	}

	// due
	opts.PKI.RenewTime = "2h"
	if !IsCertificateRenewalDue(readCert, opts) {
		t.Fatalf("Certificate expiry check failed. Not marked as due for renewal when it should be!")
	}

	// forece renew
	opts.PKI.ForceRenew = true
	if !IsCertificateRenewalDue(readCert, opts) {
		t.Fatalf("Certificate expiry check failed. Force renewal flag not working!")
	}
}
