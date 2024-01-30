package cert

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	log "github.com/sirupsen/logrus"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

type Updater interface {
	WriteCertificate(parsedCertBundle *certutil.ParsedCertBundle, options cli.Options)
	ReadCertificate(options cli.Options) *x509.Certificate
	getSpecifier() string
	enabled(options cli.Options) bool
}

// getUpdaters returns a slice of available certificate updaters
func getUpdaters() []Updater {
	return []Updater{
		&PEMFile{},
		&JKS{},
		&PKCS12{},
	}
}

// RequestCertificate returns the parsed certificate request response from vault
func RequestCertificate(client *api.Client, options cli.Options) *certutil.ParsedCertBundle {
	log.Println("Requesting certificate...")

	rawCertData, err := client.Logical().
		Write(fmt.Sprintf("%s/issue/%s", options.PKI.Mount, options.PKI.RoleName), map[string]interface{}{
			"common_name":          options.PKI.CommonName,
			"alt_names":            options.PKI.AltNames,
			"ip_sans":              options.PKI.IPSans,
			"ttl":                  options.PKI.TTL,
			"exclude_cn_from_sans": options.PKI.ExcludeSans,
			"private_key_format":   options.PKI.PrivateKeyFormat,
		})
	if err != nil {
		log.Fatalf("Error issues certificate request: %s", err.Error())
	}

	log.Println("Certificate data received.")

	certData, parseErr := certutil.ParsePKIMap(rawCertData.Data)
	if parseErr != nil {
		log.Fatalf("Error parsing certificate: %s", parseErr.Error())
	}

	return certData
}

// certificatesEqualOrInitial will return true when all certificates are equal or if some of them are nil and others are equal. Returns false otherwise. Additional the uniqie certificate will be returned if possible.
func certificatesEqualOrInitial(certs ...*x509.Certificate) (bool, *x509.Certificate) {
	var prev *x509.Certificate
	for _, cert := range certs {
		if prev == nil {
			prev = cert
		}
		if cert != nil && !cert.Equal(prev) {
			return false, nil
		}
	}
	return true, prev
}

// CheckCurrentCertificates reads all current ceritifactes and verifies whether they are equal. Returns a slice of all enabled cert specifiers, whether they are equal and the current certificate
func CheckCurrentCertificates(options cli.Options) ([]string, bool, *x509.Certificate) {
	certSpecifiers := []string{}
	var givenCerts []*x509.Certificate

	for _, u := range getUpdaters() {
		if u.enabled(options) {
			givenCerts = append(givenCerts, u.ReadCertificate(options))
			certSpecifiers = append(certSpecifiers, u.getSpecifier())
		}
	}

	equal, currentCert := certificatesEqualOrInitial(givenCerts...)
	return certSpecifiers, equal, currentCert
}

// WriteCertificates writes all certificates that should be updated
func WriteCertificates(parsedCertBundle *certutil.ParsedCertBundle, options cli.Options) {
	for _, u := range getUpdaters() {
		if u.enabled(options) {
			u.WriteCertificate(parsedCertBundle, options)
		}
	}
}

// IsCertificateRenewalDue checks a certificates expiry based on selected options
func IsCertificateRenewalDue(cert *x509.Certificate, options cli.Options) bool {
	if options.PKI.ForceRenew {
		log.Println("Force renewal is activated. Skipping renewal due check...")
		return true
	}

	log.Println("Checking certificate expiry...")

	if cert != nil {
		// check if certificate is due for renewal
		if options.PKI.RenewTime != "" {
			renewDuration, timeErr := time.ParseDuration(options.PKI.RenewTime)
			if timeErr != nil {
				log.Fatalf(
					"Unable to parse renew_duration %s: %s",
					options.PKI.RenewTime,
					timeErr.Error(),
				)
			}

			if time.Now().Add(renewDuration).After(cert.NotAfter) {
				log.Printf("Certificate due for renewal, expires %s", cert.NotAfter)
				return true
			}
			log.Printf(
				"Certificate not yet due for renewal, will be renewed %s before expiry (%s)",
				renewDuration,
				cert.NotAfter,
			)
		} else {
			// calculate percentage
			if (options.PKI.RenewPercent < 0.0) || (options.PKI.RenewPercent > 1.0) {
				log.Fatalf("Error: renew_percent must be a value between 0.0 and 1.0, got: %f", options.PKI.RenewPercent)
			}

			ttl := cert.NotAfter.Sub(cert.NotBefore)
			percSecs := ttl.Seconds() * options.PKI.RenewPercent
			duration, timeErr := time.ParseDuration(fmt.Sprintf("%fs", percSecs))
			if timeErr != nil {
				log.Fatalf("Unable to parse / calculate renew_percent %s: %s", options.PKI.RenewTime, timeErr.Error())
			}

			if time.Now().After(cert.NotBefore.Add(duration)) {
				log.Printf("Certificate due for renewal, expires %s", cert.NotAfter)
				return true
			}
			log.Printf("Certificate not yet due for renewal, will be renewed after: %s (%s after creation)", cert.NotBefore.Add(duration), duration)
		}

		return false
	}

	log.Printf("No certificate found at: %s. Skipping renewal due check...", options.PKI.CertPath)
	return true
}

// HasCertificateDataChanged verifies whether the requested data matches the data from an already existing certificate on the specified location.
// This ensures that no certificate is overwritten by mistake
func HasCertificateDataChanged(cert *x509.Certificate, options cli.Options) bool {
	// check common name
	if !strings.EqualFold(cert.Subject.CommonName, options.PKI.CommonName) {
		log.Printf(
			"Common name changed: old(%s) vs new(%s)",
			cert.Subject.CommonName,
			options.PKI.CommonName,
		)
		return true
	}

	// check dns sans
	dnsNames := strings.Split(options.PKI.AltNames, ",")
	if dnsNames[0] != "" {
		dnsNames = append(dnsNames, strings.ToLower(cert.Subject.CommonName))
	} else {
		dnsNames[0] = strings.ToLower(cert.Subject.CommonName)
	}

	if len(cert.DNSNames) != len(dnsNames) {
		log.Printf("Dns alt names changed: old(%s) vs new(%s)", cert.DNSNames, dnsNames)
		return true
	}

	for _, sn := range cert.DNSNames {
		if !contains(dnsNames, strings.ToLower(sn)) {
			log.Printf("Dns alt names changed: old(%s) vs new(%s)", cert.DNSNames, dnsNames)
			return true
		}
	}

	// check ip sans
	ipSans := strings.Split(options.PKI.IPSans, ",")
	if (ipSans[0] == "") && (len(ipSans) == 1) {
		ipSans = []string{}
	}

	if len(ipSans) != len(cert.IPAddresses) {
		log.Printf("IP SANs changed: old(%s) vs new(%s)", cert.IPAddresses, ipSans)
		return true
	}

	for _, ip := range cert.IPAddresses {
		if !contains(ipSans, ip.String()) {
			log.Printf("IP SANs changed: old(%s) vs new(%s)", cert.IPAddresses, ipSans)
			return true
		}
	}
	return false
}

// contains checks if array contains string
func contains(array []string, s string) bool {
	for _, i := range array {
		if i == s {
			return true
		}
	}
	return false
}
