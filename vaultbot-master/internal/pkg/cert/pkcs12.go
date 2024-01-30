package cert

import (
	"crypto/rand"
	"crypto/x509"
	"log"
	"os"
	"strconv"

	"github.com/hashicorp/vault/sdk/helper/certutil"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

type PKCS12 struct{}

func (p *PKCS12) enabled(options cli.Options) bool {
	return options.PKI.PKCS12Path != ""
}

func (p *PKCS12) getSpecifier() string {
	return "pkcs12"
}

// ReadCertificate parses an existing certificate at the specified PKCS#12 KeyStore
func (p *PKCS12) ReadCertificate(options cli.Options) *x509.Certificate {
	data := readDataFromPKCS12(options)
	return decodePKCS12(options, data)
}

func readDataFromPKCS12(options cli.Options) []byte {
	data, readError := os.ReadFile(options.PKI.PKCS12Path)
	if data == nil {
		log.Printf(
			"No initial PKCS#12 KeyStore or is empty: %s : %s",
			options.PKI.PKCS12Path,
			readError,
		)
		return nil
	}
	if readError != nil {
		log.Fatalf("Failed to read PKCS#12 KeyStore: %s", readError)
	}

	return data
}

func decodePKCS12(options cli.Options, data []byte) *x509.Certificate {
	if data == nil {
		log.Printf("No data. Skipping decoding")
		return nil
	}

	_, certificate, _, decodeError := pkcs12.DecodeChain(data, options.PKI.PKCS12Password)
	if decodeError != nil {
		log.Fatalf("Failed to decode PKCS#12 KeyStore: %s", decodeError)
		return nil
	}
	return certificate
}

// WriteCertificate persists a certificate bundle to the PKCS#12 KeyStore
func (p *PKCS12) WriteCertificate(
	parsedCertBundle *certutil.ParsedCertBundle,
	options cli.Options,
) {
	data := encodePKCS12Bundle(parsedCertBundle, options)
	writeToPKCS12Bundle(options, data)
}

func encodePKCS12Bundle(parsedCertBundle *certutil.ParsedCertBundle, options cli.Options) []byte {
	certificate := parsedCertBundle.Certificate
	privKey := parsedCertBundle.PrivateKey
	caCerts := certBlocksToCertificates(parsedCertBundle.CAChain)

	data, decodeErr := pkcs12.Encode(
		rand.Reader,
		privKey,
		certificate,
		caCerts,
		options.PKI.PKCS12Password,
	)
	if decodeErr != nil {
		log.Fatalf("Failed to encode PKCS#12 KeyStore: %s", decodeErr)
	}
	return data
}

func writeToPKCS12Bundle(options cli.Options, data []byte) {
	mode, err := strconv.ParseUint(options.PKI.PKCS12Umask, 8, 32)
	if err != nil {
		log.Fatalf("Failed to parse umask: %s", err)
	}

	writeError := os.WriteFile(options.PKI.PKCS12Path, data, os.FileMode(mode))
	if writeError != nil {
		log.Fatalf(
			"Failed to write PKCS#12 KeyStore to file: %s with umask: %s: %s",
			options.PKI.PKCS12Path,
			options.PKI.PKCS12Umask,
			writeError,
		)
	}
}

func certBlocksToCertificates(caBlock []*certutil.CertBlock) []*x509.Certificate {
	certificates := make([]*x509.Certificate, len(caBlock))
	for i := 0; i < len(caBlock); i++ {
		certificates[i] = caBlock[0].Certificate
	}
	return certificates
}
