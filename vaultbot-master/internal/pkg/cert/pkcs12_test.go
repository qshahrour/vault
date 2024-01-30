package cert

import (
	"os"
	"testing"

	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
	"gitlab.com/msvechla/vaultbot/internal/pkg/vault"
)

func TestReadNonExistentPKCS12(t *testing.T) {
	opts := cli.Options{}
	opts.PKI.PKCS12Path = "my/pfx.p12"
	opts.PKI.PKCS12Password = "ChangeIt"

	pkcs12Updater := PKCS12{}
	keyStore := pkcs12Updater.ReadCertificate(opts)
	if keyStore != nil {
		t.Fatalf("Error with non-existent PKCS12, should be nil result")
	}
}

func TestWriteNewPKCS12(t *testing.T) {

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

	opts.PKI.PKCS12Path = "../../../testoutput/pfx.p12"
	opts.PKI.PKCS12Password = "ChangeIt"
	opts.PKI.PKCS12Umask = "0600"

	opts.Verbose = true
	opts.Logfile = "../../../testoutput/log.log"

	t.Log("Test Init")

	client := vault.CreateClient(opts)

	c := RequestCertificate(client, opts)

	if c == nil {
		t.Fatalf("Error initating certificate request for PKCS12")
	}

	t.Log("Test #1")

	pkcs12Updater := PKCS12{}
	pkcs12Updater.WriteCertificate(c, opts)
	_, fileStatErr := os.Stat(opts.PKI.PKCS12Path)

	if os.IsNotExist(fileStatErr) {
		t.Fatalf("PKCS12 file has not been created")
	} else {
		t.Log("Test #1: File has been created successfully")
	}

	t.Log("Test #2")

	readCert := pkcs12Updater.ReadCertificate(opts)

	if readCert == nil {
		t.Fatalf("Certificate cannot be read from PKCS12 file")
	} else {
		t.Log("Test #2: Certificate has been read from PKCS12 file successfully")
	}

	t.Log("Test #3")

	if readCert.Subject.CommonName == opts.PKI.CommonName {
		t.Log("Test #3: Certificate data has been validated from PKCS12 file successfully")
	} else {
		t.Fatalf("Certificate from PKCS12 file is not the created")
	}
}

func TestDataHasChangedFromPKCS12(t *testing.T) {
	opts := cli.Options{}

	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"

	opts.PKI.CommonName = "vaultbot.test"
	opts.PKI.Mount = "pki"
	opts.PKI.RoleName = "example-dot-com"
	opts.PKI.RenewPercent = 0.7

	opts.PKI.PKCS12Path = "../../../testoutput/pfx-changed.p12"
	opts.PKI.PKCS12Password = "ChangeIt"
	opts.PKI.PKCS12Umask = "0600"

	opts.Verbose = true
	opts.Logfile = "../../../testoutput/log.log"

	t.Log("Test Init")

	client := vault.CreateClient(opts)
	cert := RequestCertificate(client, opts)

	if cert == nil {
		t.Fatalf("Error initating certificate request for PKCS12")
	}

	pkcs12Updater := PKCS12{}
	pkcs12Updater.WriteCertificate(cert, opts)

	readCert := pkcs12Updater.ReadCertificate(opts)

	t.Log("Test #1")

	changed := HasCertificateDataChanged(readCert, opts)
	if changed {
		t.Fatal("Certificate data changed, when it shouldnt!")
	} else {
		t.Log("Test #1: OK, data has not changed")
	}

	t.Log("Test #2: change IPSans")

	// IP SANs len changed, does not match created cert
	opts.PKI.IPSans = "127.0.0.1,192.168.0.1"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("IP SANs len did not changed, when it should!")
	} else {
		t.Log("Test #2: OK, data has changed")
	}

	t.Log("Test #3: change IPSans")

	// IP SANs fields changed, does not match created cert
	opts.PKI.IPSans = "192.168.0.1"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("IP SANs field did not changed, when it should!")
	} else {
		t.Log("Test #3: OK, data has changed")
	}

	t.Log("Test #4: change DNS alt names")

	// dns alt names len changed, does not match created cert
	opts.PKI.AltNames = "helloworld.com"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Dns alt names len did not changed, when it should!")
	} else {
		t.Log("Test #4: OK, data has changed")
	}

	t.Log("Test #5: change DNS alt names")

	// dns alt names fields changed, does not match created cert
	opts.PKI.AltNames = "helloworld.com,changed.com"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Dns alt names field did not changed, when it should!")
	} else {
		t.Log("Test #5: OK, data has changed")
	}

	t.Log("Test #6: change common name")

	// common name changed, does not match created cert
	opts.PKI.AltNames = "testing.test,helloworld.com"
	opts.PKI.CommonName = "VaultBot.Changed"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Certificate data did not change, when it should!")
	} else {
		t.Log("Test #6: OK, data has changed")
	}
}
