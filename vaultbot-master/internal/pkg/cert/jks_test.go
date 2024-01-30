package cert

import (
	"testing"

	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
	"gitlab.com/msvechla/vaultbot/internal/pkg/vault"
)

func TestReadNonExistentJKS(t *testing.T) {
	keyStore := readKeyStore("my/jks.jks", []byte("ChangeIt"))

	if keyStore != nil {
		t.Fatalf("Error with non-existent JKS, should be nil result")
	}
}

func TestWriteNewJKS(t *testing.T) {

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

	opts.PKI.JKSPath = "../../../testoutput/jks.jks"
	opts.PKI.JKSPassword = "ChangeIt"
	opts.PKI.JKSCertAlias = "Cert"
	opts.PKI.JKSCAChainAlias = "Chain"
	opts.PKI.JKSPrivKeyAlias = "Key"

	opts.Verbose = true
	opts.Logfile = "../../../testoutput/log.log"

	t.Log("Test Init")

	client := vault.CreateClient(opts)
	c := RequestCertificate(client, opts)

	if c == nil {
		t.Fatalf("Error initating certificate request for JKS")
	}

	t.Log("Test #1")

	jksUpdater := JKS{}
	jksUpdater.WriteCertificate(c, opts)
	keyStore := readKeyStore(opts.PKI.JKSPath, []byte(opts.PKI.JKSPassword))

	if keyStore == nil {
		t.Fatalf("JKS file has not been created")
	} else {
		t.Log("Test #1: File has been created successfully")
	}

	t.Log("Test #2")

	readCert := jksUpdater.ReadCertificate(opts)

	if readCert == nil {
		t.Fatalf("Certificate cannot be read from JKS file")
	} else {
		t.Log("Test #2: Certificate has been read from JKS file successfully")
	}

	t.Log("Test #3")

	if readCert.Subject.CommonName == opts.PKI.CommonName {
		t.Log("Test #3: Certificate data has been validated from JKS file successfully")
	} else {
		t.Fatalf("Certificate from JKS file is not the created")
	}

}

func TestDataHasChangedFromJKS(t *testing.T) {
	opts := cli.Options{}

	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"

	opts.PKI.CommonName = "vaultbot.test"
	opts.PKI.Mount = "pki"
	opts.PKI.RoleName = "example-dot-com"
	opts.PKI.RenewPercent = 0.7

	opts.PKI.JKSPath = "../../../testoutput/jks-changed.jks"
	opts.PKI.JKSPassword = "ChangeIt"
	opts.PKI.JKSCertAlias = "Cert"
	opts.PKI.JKSCAChainAlias = "Chain"
	opts.PKI.JKSPrivKeyAlias = "Key"

	opts.Verbose = true
	opts.Logfile = "../../../testoutput/log.log"

	t.Log("Test Init")

	client := vault.CreateClient(opts)
	cert := RequestCertificate(client, opts)

	if cert == nil {
		t.Fatalf("Error initating certificate request for JKS")
	}

	jksUpdater := JKS{}
	jksUpdater.WriteCertificate(cert, opts)

	readCert := jksUpdater.ReadCertificate(opts)

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

func TestHasDataChangedNoSansFromJKS(t *testing.T) {
	opts := cli.Options{}

	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"

	opts.PKI.CommonName = "vaultbot.test"
	opts.PKI.Mount = "pki"
	opts.PKI.RoleName = "example-dot-com"
	opts.PKI.RenewPercent = 0.7

	opts.PKI.JKSPath = "../../../testoutput/jks-changed2.jks"
	opts.PKI.JKSPassword = "ChangeIt"
	opts.PKI.JKSCertAlias = "Cert"
	opts.PKI.JKSCAChainAlias = "Chain"
	opts.PKI.JKSPrivKeyAlias = "Key"

	opts.Verbose = true
	opts.Logfile = "../../../testoutput/log.log"

	t.Log("Test Init")

	client := vault.CreateClient(opts)
	cert := RequestCertificate(client, opts)

	if cert == nil {
		t.Fatalf("Error initating certificate request for JKS")
	}

	jksUpdater := JKS{}
	jksUpdater.WriteCertificate(cert, opts)

	readCert := jksUpdater.ReadCertificate(opts)

	t.Log("Test #1")

	// nothing changed, match created cert
	opts.PKI.CommonName = "VaultBot.Test"
	opts.PKI.IPSans = ""
	opts.PKI.AltNames = ""

	changed := HasCertificateDataChanged(readCert, opts)
	if changed {
		t.Fatal("Certificate data changed, when it shouldnt!")
	} else {
		t.Log("Test #1: OK, data has not changed")
	}

	t.Log("Test #2")

	// IP SANs len changed, does not match created cert
	opts.PKI.IPSans = "127.0.0.1,192.168.0.1"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("IP SANs len did not changed, when it should!")
	} else {
		t.Log("Test #2: OK, data has changed")
	}

	t.Log("Test #3")

	// IP SANs fields changed, does not match created cert
	opts.PKI.IPSans = "192.168.0.1"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("IP SANs field did not changed, when it should!")
	} else {
		t.Log("Test #3: OK, data has changed")
	}

	t.Log("Test #4")

	// dns alt names len changed, does not match created cert
	opts.PKI.AltNames = "helloworld.com"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Dns alt names len did not changed, when it should!")
	} else {
		t.Log("Test #4: OK, data has changed")
	}

	t.Log("Test #5")

	// dns alt names fields changed, does not match created cert
	opts.PKI.AltNames = "helloworld.com,changed.com"
	changed = HasCertificateDataChanged(readCert, opts)
	if !changed {
		t.Fatal("Dns alt names field did not changed, when it should!")
	} else {
		t.Log("Test #5: OK, data has changed")
	}

	t.Log("Test #6")

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
