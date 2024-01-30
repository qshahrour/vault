package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gitlab.com/msvechla/vaultbot/internal/pkg/auth"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cert"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
	"gitlab.com/msvechla/vaultbot/internal/pkg/vault"

	//JKS extension dependencies
	"github.com/kami-zh/go-capturer"
)

var dirPath string
var certPath string
var caPath string
var JKSPath string
var PKCSPath string
var privkeyPath string

func TestMain(m *testing.M) {
	// create test cert
	dirPath = setupTestFolder()
	certPath = fmt.Sprintf("%s/cert.pem", dirPath)
	caPath = fmt.Sprintf("%s/ca.pem", dirPath)
	JKSPath = fmt.Sprintf("%s/jks.jks", dirPath)
	PKCSPath = fmt.Sprintf("%s/pfx.p12", dirPath)
	privkeyPath = fmt.Sprintf("%s/key.pem", dirPath)

	// run tests
	code := m.Run()

	// clean up on test exit
	//defer os.RemoveAll(dirPath)
	os.Exit(code)
}

func TestSetupLogging(t *testing.T) {
	setupLogging(cli.Options{Logfile: fmt.Sprintf("%s/test.log", dirPath)})
}

func TestCheckAuthentication(t *testing.T) {
	opts := cli.Options{}

	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"

	client := vault.CreateClient(opts)
	auth.CheckAuthentication(client)
}

func TestAppRole(t *testing.T) {
	opts := cli.Options{}

	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"
	opts.Vault.AppRoleMount = "approle"

	// setup approle backend for testing
	client := vault.CreateClient(opts)

	resp, err := client.Logical().Write(fmt.Sprintf("auth/%s/role/my-role/secret-id", opts.Vault.AppRoleMount), nil)
	assert.NoError(t, err, "Error creating AppRole secret-id")

	opts.Vault.AppRoleSecretID = resp.Data["secret_id"].(string)

	resp, err = client.Logical().Read(fmt.Sprintf("auth/%s/role/my-role/role-id", opts.Vault.AppRoleMount))
	assert.NoError(t, err, "Error reading AppRole role-id")

	opts.Vault.AppRoleRoleID = resp.Data["role_id"].(string)

	// test the newly setup AppRole authentication backend
	opts.Vault.AuthMethod = "approle"

	a := auth.AppRoleAuthenticater{}
	err = a.Authenticate(opts, client)
	assert.NoError(t, err)

	auth.CheckAuthentication(client)
}

func TestEndToEnd(t *testing.T) {
	opts := cli.Options{}

	opts.PKI.CertPath = fmt.Sprintf("%s/e2eCert.pem", dirPath)
	opts.PKI.CAChainPath = fmt.Sprintf("%s/e2eCA.pem", dirPath)
	opts.PKI.PrivKeyPath = fmt.Sprintf("%s/e2eKey.pem", dirPath)
	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"

	opts.PKI.CommonName = "vaultbot.test"
	opts.PKI.AltNames = "testing.com"
	opts.PKI.IPSans = "127.0.0.1,192.168.0.1"
	opts.PKI.Mount = "pki"
	opts.PKI.RoleName = "example-dot-com"
	opts.PKI.RenewPercent = 0.7

	opts.Verbose = true
	opts.Logfile = "./vaulbottest/log.log"

	t.Log("Test #1")
	// initial run test
	out := capturer.CaptureStdout(func() {
		run(opts)
	})

	t.Log(out)

	pemUpdater := cert.PEMFile{}
	cert := pemUpdater.ReadCertificate(opts)
	if cert == nil {
		t.Fatal("Failed end to end test, no certificate found")
	}

	// check if file was not modified, because not yet expired
	oldHash := getFileHash(fmt.Sprintf("%s/e2eCert.pem", dirPath))

	// run again, should not modify
	t.Log("Test #2")
	out = capturer.CaptureStdout(func() {
		run(opts)
	})

	t.Log(out)

	newHash := getFileHash(fmt.Sprintf("%s/e2eCert.pem", dirPath))
	if oldHash != newHash {
		t.Fatalf("Error in end to end test, certificate was modified when it was not expired!")
	}

	// run again, should modify now
	opts.PKI.RenewPercent = 0.000000001
	opts.PKI.PEMBundlePath = fmt.Sprintf("%s/e2eBundle.pem", dirPath)
	opts.RenewHook = fmt.Sprintf("touch %s/test.txt", dirPath)
	t.Log("Test #3")

	out = capturer.CaptureStdout(func() {
		run(opts)
	})

	t.Log(out)

	renewHash := getFileHash(fmt.Sprintf("%s/e2eCert.pem", dirPath))
	if renewHash == newHash {
		t.Fatalf("Error in end to end test, certificate was not modified, although renew_percent should trigger!")
	}
}

func TestRenewSelf(t *testing.T) {
	opts := cli.Options{}
	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myPeriodicToken"

	client := vault.CreateClient(opts)
	vault.RenewSelf(client, opts)
}

func TestRequestCertificate(t *testing.T) {

	cn := "vaultbot.test"
	altNames := "vaultbot.test"
	ipSANS := "127.0.0.1,192.168.0.1"

	opts := cli.Options{}

	opts.PKI.CertPath = certPath
	opts.PKI.CAChainPath = caPath
	opts.PKI.PrivKeyPath = privkeyPath
	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"

	opts.PKI.CommonName = cn
	opts.PKI.AltNames = altNames
	opts.PKI.IPSans = ipSANS
	opts.PKI.Mount = "pki"
	opts.PKI.RoleName = "example-dot-com"

	client := vault.CreateClient(opts)
	c := cert.RequestCertificate(client, opts)
	if c == nil {
		t.Fatal("Error requesting certificate")
	}

	pemUpdater := cert.PEMFile{}
	pemUpdater.WriteCertificate(c, opts)
	certRead := pemUpdater.ReadCertificate(opts)
	if certRead.Subject.CommonName != cn {
		t.Fatal("Received CN does not match requested CN!")
	}

}

func TestJKSEndToEnd(t *testing.T) {
	opts := cli.Options{}

	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"

	opts.PKI.CommonName = "vaultbot.test"
	opts.PKI.AltNames = "testing.com"
	opts.PKI.IPSans = "127.0.0.1,192.168.0.1"
	opts.PKI.Mount = "pki"
	opts.PKI.RoleName = "example-dot-com"
	opts.PKI.RenewPercent = 0.7

	opts.PKI.JKSPath = fmt.Sprintf("%s/jks-e2e.jks", dirPath)
	opts.PKI.JKSPassword = "ChangeIt"
	opts.PKI.JKSCertAlias = "Cert"
	opts.PKI.JKSCAChainAlias = "Chain"
	opts.PKI.JKSPrivKeyAlias = "Key"

	opts.Verbose = true
	opts.Logfile = "./testoutput/log.log"

	t.Log("Test #1")
	// initial run test
	out := capturer.CaptureStdout(func() {
		run(opts)
	})

	t.Log(out)

	jksUpdater := cert.JKS{}
	c := jksUpdater.ReadCertificate(opts)
	if c == nil {
		t.Fatal("Failed end to end test, no certificate found")
	} else {
		t.Log("Test #1: Certificate can be read")
	}

	// check if file was not modified, because not yet expired
	oldCert := c

	// run again, should not modify
	t.Log("Test #2")
	out = capturer.CaptureStdout(func() {
		run(opts)
	})

	t.Log(out)

	c = jksUpdater.ReadCertificate(opts)

	newCert := c

	if !(oldCert.Equal(newCert)) {
		t.Fatalf("Error in end to end test, certificate was modified when it was not expired!")
	} else {
		t.Log("Test #2: OK, data has not changed")
	}

	// run again, should modify now
	opts.PKI.RenewPercent = 0.000000001
	opts.RenewHook = fmt.Sprintf("touch %s/test.txt", dirPath)
	t.Log("Test #3")

	out = capturer.CaptureStdout(func() {
		run(opts)
	})

	t.Log(out)

	c = jksUpdater.ReadCertificate(opts)

	renewCert := c

	if renewCert.Equal(newCert) {
		t.Fatalf("Error in end to end test, certificate was not modified, although renew_percent should trigger!")
	} else {
		t.Log("Test #3: OK, data has changed")
	}
}

func TestHasDataChangedNoSansFromPKCS12(t *testing.T) {
	opts := cli.Options{}

	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"

	opts.PKI.CommonName = "vaultbot.test"
	opts.PKI.Mount = "pki"
	opts.PKI.RoleName = "example-dot-com"
	opts.PKI.RenewPercent = 0.7

	opts.PKI.PKCS12Path = fmt.Sprintf("%s/pfx-changed2.p12", dirPath)
	opts.PKI.PKCS12Password = "ChangeIt"
	opts.PKI.PKCS12Umask = "0600"

	opts.Verbose = true
	opts.Logfile = "./testoutput/log.log"

	t.Log("Test Init")

	client := vault.CreateClient(opts)
	c := cert.RequestCertificate(client, opts)

	if c == nil {
		t.Fatalf("Error initating certificate request for JKS")
	}

	pkcs12Updater := cert.PKCS12{}
	pkcs12Updater.WriteCertificate(c, opts)

	readCert := pkcs12Updater.ReadCertificate(opts)

	t.Log("Test #1")

	// nothing changed, match created cert
	opts.PKI.CommonName = "VaultBot.Test"
	opts.PKI.IPSans = ""
	opts.PKI.AltNames = ""

	changed := cert.HasCertificateDataChanged(readCert, opts)
	if changed {
		t.Fatal("Certificate data changed, when it shouldnt!")
	} else {
		t.Log("Test #1: OK, data has not changed")
	}

	t.Log("Test #2")

	// IP SANs len changed, does not match created cert
	opts.PKI.IPSans = "127.0.0.1,192.168.0.1"
	changed = cert.HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("IP SANs len did not changed, when it should!")
	} else {
		t.Log("Test #2: OK, data has changed")
	}

	t.Log("Test #3")

	// IP SANs fields changed, does not match created cert
	opts.PKI.IPSans = "192.168.0.1"
	changed = cert.HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("IP SANs field did not changed, when it should!")
	} else {
		t.Log("Test #3: OK, data has changed")
	}

	t.Log("Test #4")

	// dns alt names len changed, does not match created cert
	opts.PKI.AltNames = "helloworld.com"
	changed = cert.HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Dns alt names len did not changed, when it should!")
	} else {
		t.Log("Test #4: OK, data has changed")
	}

	t.Log("Test #5")

	// dns alt names fields changed, does not match created cert
	opts.PKI.AltNames = "helloworld.com,changed.com"
	changed = cert.HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Dns alt names field did not changed, when it should!")
	} else {
		t.Log("Test #5: OK, data has changed")
	}

	t.Log("Test #6")

	// common name changed, does not match created cert
	opts.PKI.AltNames = "testing.test,helloworld.com"
	opts.PKI.CommonName = "VaultBot.Changed"
	changed = cert.HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Certificate data did not change, when it should!")
	} else {
		t.Log("Test #6: OK, data has changed")
	}
}

func TestPKCS12EndToEnd(t *testing.T) {
	opts := cli.Options{}

	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"

	opts.PKI.CommonName = "vaultbot.test"
	opts.PKI.AltNames = "testing.com"
	opts.PKI.IPSans = "127.0.0.1,192.168.0.1"
	opts.PKI.Mount = "pki"
	opts.PKI.RoleName = "example-dot-com"
	opts.PKI.RenewPercent = 0.7

	opts.PKI.PKCS12Path = fmt.Sprintf("%s/pfx-e2e.p12", dirPath)
	opts.PKI.PKCS12Password = "ChangeIt"
	opts.PKI.PKCS12Umask = "0600"

	opts.Verbose = true
	opts.Logfile = "./testoutput/log.log"

	t.Log("Test #1")
	// initial run test
	out := capturer.CaptureStdout(func() {
		run(opts)
	})

	t.Log(out)

	pkcs12Updater := cert.PKCS12{}
	c := pkcs12Updater.ReadCertificate(opts)
	if c == nil {
		t.Fatal("Failed end to end test, no certificate found")
	} else {
		t.Log("Test #1: Certificate can be read")
	}

	// check if file was not modified, because not yet expired
	oldCert := c

	// run again, should not modify
	t.Log("Test #2")
	out = capturer.CaptureStdout(func() {
		run(opts)
	})

	t.Log(out)

	c = pkcs12Updater.ReadCertificate(opts)

	newCert := c

	if !(oldCert.Equal(newCert)) {
		t.Fatalf("Error in end to end test, certificate was modified when it was not expired!")
	} else {
		t.Log("Test #2: OK, data has not changed")
	}

	// run again, should modify now
	opts.PKI.RenewPercent = 0.000000001
	opts.RenewHook = fmt.Sprintf("touch %s/test.txt", dirPath)
	t.Log("Test #3")

	out = capturer.CaptureStdout(func() {
		run(opts)
	})

	t.Log(out)

	c = pkcs12Updater.ReadCertificate(opts)

	renewCert := c

	if renewCert.Equal(newCert) {
		t.Fatalf("Error in end to end test, certificate was not modified, although renew_percent should trigger!")
	} else {
		t.Log("Test #3: OK, data has changed")
	}
}

// creates a temp folder to store certificates
func setupTestFolder() string {
	dir := "./testoutput"
	return dir
}

func getFileHash(file string) string {
	f, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func ExtendIPSAN(slice []net.IP, element net.IP) []net.IP {
	n := len(slice)
	if n == cap(slice) {
		// Slice is full; must grow.
		// We double its size and add 1, so if the size is zero we still grow.
		newSlice := make([]net.IP, len(slice), 2*len(slice)+1)
		copy(newSlice, slice)
		slice = newSlice
	}
	slice = slice[0 : n+1]
	slice[n] = element
	return slice
}
