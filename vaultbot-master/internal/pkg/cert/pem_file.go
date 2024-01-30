package cert

import (
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/hashicorp/vault/sdk/helper/certutil"
	log "github.com/sirupsen/logrus"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

type PEMFile struct{}

func (p *PEMFile) enabled(options cli.Options) bool {
	return options.PKI.CertPath != ""
}

func (p *PEMFile) getSpecifier() string {
	return "pem_file"
}

// ReadCertificate parses an existing certificate at the specified location
func (p *PEMFile) ReadCertificate(options cli.Options) *x509.Certificate {
	if _, err := os.Stat(options.PKI.CertPath); err == nil {
		certFile, fileErr := os.ReadFile(options.PKI.CertPath)
		if fileErr != nil {
			log.Fatalf("Unable to read certificate at %s: %s", options.PKI.CertPath, fileErr)
		}

		block, _ := pem.Decode(certFile)
		if block == nil {
			log.Fatalln("Failed to decode certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse certificate at %s: %s", options.PKI.CertPath, err.Error())
		}
		return cert
	}
	return nil
}

// WriteCertificate persists a certificate bundle to the filesystem in PEM format
func (p *PEMFile) WriteCertificate(
	parsedCertBundle *certutil.ParsedCertBundle,
	options cli.Options,
) {
	// pem bundle
	var pemBundleOut *os.File
	var err error

	if options.PKI.PEMBundlePath != "" {
		pemBundleOut, err = os.OpenFile(
			options.PKI.PEMBundlePath,
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
			0600,
		)
		if err != nil {
			log.Fatalf("Failed to open %s for writing: %s", options.PKI.PEMBundlePath, err)
		}
	}

	// private key
	keyOut, err := os.OpenFile(options.PKI.PrivKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", options.PKI.PrivKeyPath, err)
	}

	err = pem.Encode(
		keyOut,
		&pem.Block{
			Type:  string(parsedCertBundle.PrivateKeyFormat),
			Bytes: parsedCertBundle.PrivateKeyBytes,
		},
	)
	if err != nil {
		log.Fatalf("Failed to encode private key: %s", err)
	}

	if pemBundleOut != nil {
		err = pem.Encode(
			pemBundleOut,
			&pem.Block{
				Type:  string(parsedCertBundle.PrivateKeyFormat),
				Bytes: parsedCertBundle.PrivateKeyBytes,
			},
		)
		if err != nil {
			log.Fatalf("Failed to encode bundle: %s", err)
		}
	}

	err = keyOut.Close()
	if err != nil {
		log.Fatalf("Failed to close private key file: %s", err)
	}

	log.Printf("Wrote private key to: %s.", options.PKI.PrivKeyPath)

	// certificate
	certOut, err := os.Create(options.PKI.CertPath)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", options.PKI.CertPath, err)
	}

	err = pem.Encode(
		certOut,
		&pem.Block{Type: "CERTIFICATE", Bytes: parsedCertBundle.CertificateBytes},
	)
	if err != nil {
		log.Fatalf("Failed to encode certificate: %s", err)
	}

	if pemBundleOut != nil {
		err = pem.Encode(
			pemBundleOut,
			&pem.Block{Type: "CERTIFICATE", Bytes: parsedCertBundle.CertificateBytes},
		)
		if err != nil {
			log.Fatalf("Failed to encode bundle: %s", err)
		}
	}
	err = certOut.Close()
	if err != nil {
		log.Fatalf("Failed to close certificate file: %s", err)
	}

	log.Printf("Wrote certificate to: %s.", options.PKI.CertPath)

	// certificate chain
	chainOut, err := os.Create(options.PKI.CAChainPath)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", options.PKI.CAChainPath, err)
	}

	for _, cert := range parsedCertBundle.CAChain {
		err = pem.Encode(chainOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Bytes})
		if err != nil {
			log.Fatalf("Failed to encode certificate: %s", err)
		}
		if pemBundleOut != nil {
			err = pem.Encode(pemBundleOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Bytes})
			if err != nil {
				log.Fatalf("Failed to encode bundle: %s", err)
			}
		}
	}

	err = chainOut.Close()
	if err != nil {
		log.Fatalf("Failed to close certificate chain file: %s", err)
	}
	log.Printf("Wrote CA chain to: %s.", options.PKI.CAChainPath)

	if pemBundleOut != nil {
		err = pemBundleOut.Close()
		if err != nil {
			log.Fatalf("Failed to close bundle file: %s", err)
		}
		log.Printf("Wrote PEM Bundle to: %s.", options.PKI.PEMBundlePath)
	}
}
