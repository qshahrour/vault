package cert

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/pavel-v-chernykh/keystore-go"
	log "github.com/sirupsen/logrus"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

type JKS struct{}

func (j *JKS) enabled(options cli.Options) bool {
	return options.PKI.JKSPath != ""
}

func (j *JKS) getSpecifier() string {
	return "jks"
}

// ReadCertificate parses an existing certificate at the specified JKS with the specified label
func (j *JKS) ReadCertificate(options cli.Options) *x509.Certificate {
	var err error

	password := []byte(options.PKI.JKSPassword)
	defer zeroing(password)
	ks := readKeyStore(options.PKI.JKSPath, password)

	if ks == nil {
		log.Printf("No initial JKS or JKS empty at: %s : %s", options.PKI.JKSPath, err)
		return nil
	}

	if err != nil {
		log.Fatalf("Failed to open JKS at: %s with provided password for reading: %s", options.PKI.JKSPath, err)
	}

	entry := ks[strings.ToLower(options.PKI.JKSCertAlias)]

	if entry == nil {
		log.Println("No cert in JKS")
		return nil
	}
	certEntry := entry.(*keystore.TrustedCertificateEntry)
	cert, err := x509.ParseCertificate([]byte(certEntry.Certificate.Content))

	if err != nil {
		log.Fatalf("Failed to parse certificate at JKS: %s for alias: %s : %s", options.PKI.JKSPath, options.PKI.JKSCertAlias, err.Error())
	}

	return cert
}

// WriteCertificate persists a certificate bundle to the JAVA KeyStore
func (j *JKS) WriteCertificate(parsedCertBundle *certutil.ParsedCertBundle, options cli.Options) {
	var err error
	var chain keystore.Certificate
	var bundle []keystore.Certificate

	password := []byte(options.PKI.JKSPassword)
	defer zeroing(password)
	ks := readKeyStore(options.PKI.JKSPath, password)

	if err != nil {
		if os.IsNotExist(err) {
			log.Fatalf("No initial JKS at: %s : %s", options.PKI.JKSPath, err)
			ks = keystore.KeyStore{}
		} else {
			log.Fatalf("Failed to open JKS at: %s with provided password for reading: %s", options.PKI.JKSPath, err)
		}
	}

	if ks == nil {
		ks = keystore.KeyStore{}
	}

	cert := keystore.Certificate{
		Type:    "X509",
		Content: []byte(parsedCertBundle.CertificateBytes),
	}

	entryc1 := &keystore.TrustedCertificateEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		Certificate: cert,
	}

	ks[strings.ToLower(options.PKI.JKSCertAlias)] = entryc1
	bundle = append(bundle, cert)

	log.Printf("Added Cert to the JKS structure: %s with alias %s", cert, strings.ToLower(options.PKI.JKSCertAlias))

	for index, cert := range parsedCertBundle.CAChain {
		chain = keystore.Certificate{
			Type:    "X509",
			Content: []byte(cert.Bytes),
		}

		entryc2 := &keystore.TrustedCertificateEntry{
			Entry: keystore.Entry{
				CreationDate: time.Now(),
			},
			Certificate: chain,
		}

		ks[strings.ToLower(fmt.Sprintf("%s%s%d", options.PKI.JKSCAChainAlias, "_", index))] = entryc2
		bundle = append(bundle, chain)
		log.Printf("Added Cert to chain in the JKS structure: %s with alias %s", chain, strings.ToLower(fmt.Sprintf("%s%s%d", options.PKI.JKSCAChainAlias, "_", index)))
	}

	log.Printf("Added Chain to the JKS structure")

	entryp := &keystore.PrivateKeyEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		PrivKey:   []byte(parsedCertBundle.PrivateKeyBytes),
		CertChain: bundle,
	}

	ks[strings.ToLower(options.PKI.JKSPrivKeyAlias)] = entryp

	log.Printf("Added Private Key to the JKS structure")

	password = []byte(options.PKI.JKSPassword)
	defer zeroing(password)
	writeKeyStore(ks, options.PKI.JKSPath, password)

}

// flusing password from var as described in https://github.com/pavel-v-chernykh/keystore-go/blob/master/examples/pem/main.go
func zeroing(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] = 0
	}
	log.Printf("Zeroed JKS passphrase")
}

// readKeyStore read a Java key store
func readKeyStore(filename string, password []byte) keystore.KeyStore {
	log.Printf("Start reading JKS: %s", filename)
	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("No initial JKS at: %s : %s", filename, err)
			return nil
		}
		log.Fatalf("Failed to open JKS at: %s with provided password for reading: %s", filename, err)
	}
	keyStore, err := keystore.Decode(f, password)
	if err != nil {
		if len(keyStore) != 0 {
			log.Fatalf("Failed to decode JKS file %s: %s  - structure %s", filename, err, keyStore)
		} else {
			log.Printf("JKS is empty: %s with %s", filename, err)
			keyStore = make(map[string]interface{})
		}
	}
	log.Printf("Read and decoded JKS: %s", filename)
	return keyStore
}

// writeKeyStore writes a key store
func writeKeyStore(keyStore keystore.KeyStore, filename string, password []byte) {
	log.Printf("Start writing JKS: %s", filename)
	o, err := os.Create(filename)
	defer o.Close()
	if err != nil {
		log.Fatalf("Failed to create JKS file %s: %s", filename, err)
	}
	err = keystore.Encode(o, keyStore, password)
	if err != nil {
		log.Fatalf("Failed to encode JKS File %s: %s - structure %s", filename, err, keyStore)
	}
	log.Printf("Wrote and coded JKS: %s", filename)
}
