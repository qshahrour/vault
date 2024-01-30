package main

import (
	"fmt"
	"os"
	"strings"

	goflags "github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"gitlab.com/msvechla/vaultbot/internal/pkg/auth"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cert"
	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
	"gitlab.com/msvechla/vaultbot/internal/pkg/vault"
)

// VaultbotVersion TODO: bump before release
const (
	VaultbotVersion = "1.14.0"
)

var options cli.Options

func main() {
	_, err := goflags.ParseArgs(&options, os.Args)
	if err != nil {
		os.Exit(1)
	}

	if options.Version {
		printVersion()
		os.Exit(0)
	}

	setupLogging(options)
	run(options)
}

// printVersion logs the current version and exits
func printVersion() {
	fmt.Printf("Vaultbot v%s\n", VaultbotVersion)
}

// setupLogging configures logarus
func setupLogging(options cli.Options) {
	log.SetFormatter(&log.JSONFormatter{})
	if options.Logfile != "" {
		file, err := os.OpenFile(options.Logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			log.SetOutput(file)
		} else {
			log.Printf("Failed to log to file, using default stderr: %s", err)
		}
	}
}

// run executes all necessary methods in order to execute vaultbot based on specified options
func run(options cli.Options) {
	log.Println("Vaultbot started...")
	if options.PKI.RoleName == "" {
		log.Fatalln("the required flag `--pki_role_name' was not specified!")
	}

	log.Printf("Running Vaultbot v%s", VaultbotVersion)
	client := vault.CreateClient(options)
	if options.Vault.RenewToken {
		vault.RenewSelf(client, options)
	}

	writeConfirmed := true
	dueForRenewal := true

	if options.PKI.JKSExport {
		log.Errorf(
			"Option `pki_jks_export` is deprecated and will be removed in a future release. Exporting to JKS is now determined based on whether `pki_jks_path` has been specified.",
		)
	}

	certSpecifiers, equal, currentCert := cert.CheckCurrentCertificates(options)

	if !equal {
		log.Fatalf(
			"%s have been specified, but the parsed certificates are not equal. Aborting.",
			strings.Join(certSpecifiers, ", "),
		)
	}

	if currentCert != nil {
		dueForRenewal = cert.IsCertificateRenewalDue(currentCert, options)

		if dueForRenewal {
			if cert.HasCertificateDataChanged(currentCert, options) {
				if !options.AutoConfirm {
					writeConfirmed = cli.UserConfirmation(
						"Requested certificate data does not match existing certificate, continue anyways?",
					)
				} else {
					log.Println("Requested certificate data does not match existing certificate, continuing anyways (auto confirmed)")
				}
			}
		}
	} else {
		log.Println("No existing certificate found, initial request.")
	}

	if writeConfirmed {
		if dueForRenewal {
			parsedCertBundle := cert.RequestCertificate(client, options)

			// write the certificates
			cert.WriteCertificates(parsedCertBundle, options)

			// execute renew hook
			if options.RenewHook != "" {
				err := os.Setenv("VAULTBOT_RENEWED_CN", options.PKI.CommonName)
				if err != nil {
					log.Fatalf(
						"Error setting environment variable VAULTBOT_RENEWED_CN for renew hook: %s",
						err,
					)
				}
				cli.ExecuteRenewHook(options.RenewHook)
			}

			log.Println("Certificate renewal finished successfully.")
		} else {
			// fail early in case no valid authentication is possible
			err := auth.CheckAuthentication(client)
			if err != nil {
				log.Fatalf("Error validating authentication: %s", err)
			}
		}
	} else {
		log.Println("Certificate renewal cancled by user.")
	}

	log.Println("Vaultbot finished successfully.")
}
