package cert

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
	"gitlab.com/msvechla/vaultbot/internal/pkg/vault"
)

func TestPKCS1PrivateKeyFormat(t *testing.T) {

	cn := "vaultbot.test"
	altNames := "vaultbot.test"
	ipSANS := "127.0.0.1,192.168.0.1"

	opts := cli.Options{}

	opts.PKI.CertPath = "../../../testoutput/cert.pem"
	opts.PKI.CAChainPath = "../../../testoutput/ca.pem"
	opts.PKI.PrivKeyPath = "../../../testoutput/key.pem"
	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"

	opts.PKI.CommonName = cn
	opts.PKI.AltNames = altNames
	opts.PKI.IPSans = ipSANS
	opts.PKI.Mount = "pki"
	opts.PKI.RoleName = "example-dot-com"

	client := vault.CreateClient(opts)
	cert := RequestCertificate(client, opts)
	if cert == nil {
		t.Fatal("Error requesting certificate")
	}

	pemFileUpdater := PEMFile{}
	pemFileUpdater.WriteCertificate(cert, opts)
	PrivateKeyBlock := readCurrentKeyBlock(opts)
	if !isPKCS1Block(PrivateKeyBlock.Type) {
		log.Fatalf("Error on private key block type")
	}
	PrivateKeyBytes := PrivateKeyBlock.Bytes
	_, err := x509.ParsePKCS1PrivateKey(PrivateKeyBytes)
	if err != nil {
		log.Fatalf("Unable to parse private RSA key")
	}
}

func TestPKCS8PrivateKeyFormat(t *testing.T) {

	cn := "vaultbot.test"
	altNames := "vaultbot.test"
	ipSANS := "127.0.0.1,192.168.0.1"

	opts := cli.Options{}

	opts.PKI.CertPath = "../../../testoutput/cert.pem"
	opts.PKI.CAChainPath = "../../../testoutput/ca.pem"
	opts.PKI.PrivKeyPath = "../../../testoutput/key.pem"
	opts.Vault.Address = "http://vault:1234"
	opts.Vault.AuthMethod = "token"
	opts.Vault.Token = "myroot"

	opts.PKI.CommonName = cn
	opts.PKI.AltNames = altNames
	opts.PKI.IPSans = ipSANS
	opts.PKI.Mount = "pki"
	opts.PKI.RoleName = "example-dot-com"
	opts.PKI.PrivateKeyFormat = "pkcs8"

	client := vault.CreateClient(opts)
	cert := RequestCertificate(client, opts)
	if cert == nil {
		t.Fatal("Error requesting certificate")
	}

	pemFileUpdater := PEMFile{}
	pemFileUpdater.WriteCertificate(cert, opts)
	PrivateKeyBlock := readCurrentKeyBlock(opts)
	if !isPKCS8Block(PrivateKeyBlock.Type) {
		log.Fatalf("Error on private key block type")
	}
	PrivateKeyBytes := PrivateKeyBlock.Bytes
	_, err := x509.ParsePKCS8PrivateKey(PrivateKeyBytes)
	if err != nil {
		log.Fatalf("Unable to parse private RSA key")
	}
}

func readCurrentKeyBlock(options cli.Options) *pem.Block {
	if _, err := os.Stat(options.PKI.PrivKeyPath); err == nil {
		PrivateKey, fileErr := ioutil.ReadFile(options.PKI.PrivKeyPath)
		if fileErr != nil {
			log.Fatalf("Unable to read Private Key at %s: %s", options.PKI.PrivKeyPath, fileErr)
		}

		pemBlock, _ := pem.Decode([]byte(PrivateKey))
		if pemBlock == nil {
			log.Fatalf("Failed to decode Private Key")
		}

		return pemBlock
	}
	return nil
}

func isPKCS1Block(blockType string) bool {
	return blockType == "RSA PRIVATE KEY"
}

func isPKCS8Block(blockType string) bool {
	return blockType == "PRIVATE KEY"
}
