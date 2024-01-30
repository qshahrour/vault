package cli

// Options used for parsing commandline args
type Options struct {
	Verbose bool `short:"v" long:"verbose" description:"Show verbose debug information"`

	// Vault Connection
	Vault struct {
		Address                    string `long:"vault_addr" env:"VAULT_ADDR" description:"The address of the Vault server expressed as a URL and port" default:"http://127.0.0.1:8200"`
		CACert                     string `long:"vault_cacert" env:"VAULT_CACERT" description:"Path to a PEM-encoded CA cert file to use to verify the Vault server SSL certificate."`
		CAPath                     string `long:"vault_capath" env:"VAULT_CAPATH" description:"Path to a directory of PEM-encoded CA cert files to verify the Vault server SSL certificate. If VAULT_CACERT is specified, its value will take precedence."`
		ClientCert                 string `long:"vault_client_cert" env:"VAULT_CLIENT_CERT" description:"Path to a PEM-encoded client certificate for TLS authentication to the Vault server."`
		ClientKey                  string `long:"vault_client_key" env:"VAULT_CLIENT_KEY" description:"Path to an unencrypted PEM-encoded private key matching the client certificate."`
		ClientTimeout              int    `long:"vault_client_timeout" env:"VAULT_CLIENT_TIMEOUT" description:"Timeout variable for the vault client."`
		Insecure                   bool   `long:"vault_skip_verify" env:"VAULT_SKIP_VERIFY" description:"If set, do not verify Vault's presented certificate before communicating with it. Setting this variable is not recommended except during testing."`
		TLSServerName              string `long:"vault_tls_server_name" env:"VAULT_TLS_SERVER_NAME" description:"If set, use the given name as the SNI host when connecting via TLS."`
		MaxRetries                 int    `long:"vault_max_retries" env:"VAULT_MAX_RETRIES" description:"The maximum number of retries when a 5xx error code is encountered."`
		Token                      string `long:"vault_token" env:"VAULT_TOKEN" description:"The Vault authentication token."`
		RenewToken                 bool   `long:"vault_renew_token" env:"RENEW_TOKEN" description:"If set, vaultbot tries to automatically renew the current token"`
		AuthMethod                 string `long:"vault_auth_method" env:"VAULT_AUTH_METHOD" description:"The method used to authenitcate to vault. Should be one of [agent, cert, approle, token, aws-iam, aws-ec2, gcp-gce, gcp-iam]" default:"token"`
		CertificateRole            string `long:"vault_certificate_role" env:"VAULT_CERTIFICATE_ROLE" description:"The certificate role to authenticate against, when using the cert auth mehtod." default:""`
		AWSAuthRole                string `long:"vault_aws_auth_role" env:"VAULT_AWS_AUTH_ROLE" description:"The role to use for AWS IAM authentication" default:""`
		AWSAuthMount               string `long:"vault_aws_auth_mount" env:"VAULT_AWS_AUTH_MOUNT" description:"The mount path for the vault AWS auth method" default:"aws"`
		AWSAuthHeader              string `long:"vault_aws_auth_header" env:"VAULT_AWS_AUTH_HEADER" description:"The header to use during vault AWS IAM authentication. If empty no header will be set" default:""`
		AWSAuthNonce               string `long:"vault_aws_auth_nonce" env:"VAULT_AWS_AUTH_NONCE" description:"The nonce to use during vault AWS EC2 authentication" default:""`
		AWSAuthNoncePath           string `long:"vault_aws_auth_nonce_path" env:"VAULT_AWS_AUTH_NONCE_PATH" description:"If set, the nonce that is used during vault AWS EC2 authentication will be written to this path" default:""`
		GCPAuthRole                string `long:"vault_gcp_auth_role" env:"VAULT_GCP_AUTH_ROLE" description:"The role to use for GCP authentication" default:""`
		GCPAuthServiceAccountEmail string `long:"vault_gcp_auth_service_account_email" env:"VAULT_GCP_AUTH_SERVICE_ACCOUNT_EMAIL" description:"The service account email to use for GCP IAM authentiation" default:""`
		GCPAuthMount               string `long:"vault_gcp_auth_mount" env:"VAULT_GCP_AUTH_MOUNT" description:"The mount path for the vault GCP auth method" default:"gcp"`
		AppRoleMount               string `long:"vault_app_role_mount" env:"VAULT_APP_ROLE_MOUNT" description:"The mount path for the AppRole backend" default:"approle"`
		AppRoleRoleID              string `long:"vault_app_role_role_id" env:"VAULT_APP_ROLE_ROLE_ID" description:"RoleID of the AppRole" default:""`
		AppRoleSecretID            string `long:"vault_app_role_secret_id" env:"VAULT_APP_ROLE_SECRET_ID" description:"SecretID belonging to AppRole" default:""`
	} `group:"Vault Options"`

	// PKI Specific
	PKI struct {
		Mount            string `long:"pki_mount" env:"PKI_MOUNT" description:"Specifies the PKI backend mount path" default:"pki"`
		RoleName         string `long:"pki_role_name" env:"PKI_ROLE_NAME" description:"Specifies the name of the role to create the certificate against"`
		CommonName       string `long:"pki_common_name" env:"PKI_COMMON_NAME" description:"Specifies the requested CN for the certificate"`
		AltNames         string `long:"pki_alt_names" env:"PKI_ALT_NAMES" description:"Specifies requested Subject Alternative Names, in a comma-delimited list"`
		IPSans           string `long:"pki_ip_sans" env:"PKI_IP_SANS" description:"Specifies requested IP Subject Alternative Names, in a comma-delimited list"`
		TTL              string `long:"pki_ttl" env:"PKI_TTL" description:"Specifies requested Time To Live"`
		ExcludeSans      bool   `long:"pki_exclude_cn_from_sans" env:"EXCLUDE_CN_FROM_SANS" description:"If set, the given common_name will not be included in DNS or Email Subject Alternate Names (as appropriate)"`
		PrivateKeyFormat string `long:"pki_private_key_format" env:"PRIVATE_KEY_FORMAT" description:"Specifies the format for marshaling the private key."`

		RenewPercent    float64 `long:"pki_renew_percent" env:"PKI_RENEW_PERCENT" description:"Percentage of requested certificate TTL, which triggers a renewal when passed (>0.00, <1.00)" default:"0.75"`
		RenewTime       string  `long:"pki_renew_time" env:"PKI_RENEW_TIME" description:"Time in hours before certificate expiry, which triggers a renewal (e.g. 12h, 1m). Takes precedence over renew_time when set."`
		ForceRenew      bool    `long:"pki_force_renew" env:"PKI_FORCE_RENEW" description:"If set, the certificate will be renewed without checking the expiry"`
		CertPath        string  `long:"pki_cert_path" env:"PKI_CERT_PATH" description:"Path to the requested / to be updated certificate"`
		CAChainPath     string  `long:"pki_cachain_path" env:"PKI_CACHAIN_PATH" description:"Path to the CA Chain of the requested / to be updated certificate" default:"chain.pem"`
		PrivKeyPath     string  `long:"pki_privkey_path" env:"PKI_PRIVKEY_PATH" description:"Path to the private key of the requested / to be updated certificate" default:"key.pem"`
		PEMBundlePath   string  `long:"pki_pembundle_path" env:"PKI_PEMBUNDLE_PATH" description:"Path to the pem bundle of the requested / to be updated certificate, private key and ca chain"`
		JKSExport       bool    `long:"pki_jks_export" env:"PKI_JKS_EXPORT" description:"DEPRECATED: export to JKS is now determined by specifying pki_jks_path"`
		JKSPath         string  `long:"pki_jks_path" env:"PKI_JKS_PATH" description:"Path to a JAVA KeyStore where the certificates should be exported"`
		JKSPassword     string  `long:"pki_jks_password" env:"PKI_JKS_PASSWORD" description:"JAVA KeyStore password" default:"ChangeIt"`
		JKSCertAlias    string  `long:"pki_jks_cert_alias" env:"PKI_JKS_CERT_ALIAS" description:"Alias in the JAVA KeyStore of the requested / to be updated certificate" default:"cert.pem"`
		JKSCAChainAlias string  `long:"pki_jks_cachain_alias" env:"PKI_JKS_CACHAIN_ALIAS" description:"Alias in the JAVA KeyStore of the CA Chain of the requested / to be updated certificate" default:"chain.pem"`
		JKSPrivKeyAlias string  `long:"pki_jks_privkey_alias" env:"PKI_JKS_PRIVKEY_ALIAS" description:"Alias in the JAVA KeyStore of the private key of the requested / to be updated certificate" default:"key.pem"`
		PKCS12Path      string  `long:"pki_pkcs12_path" env:"PKI_PKCS12_PATH" description:"Path to a PKCS#12 KeyStore where the certificates should be exported to"`
		PKCS12Umask     string  `long:"pki_pkcs12_umask" env:"PKI_PKCS12_UMASK" description:"Umask of the generated PKCS#12 KeyStore. Existing keystore will keep it's umask. Octal format required (e.g. 0644)" default:"0600"`
		PKCS12Password  string  `long:"pki_pkcs12_password" env:"PKI_PKCS12_PASSWORD" description:"Default password is \"ChangeIt\", a commonly-used password for PKCS#12 files. Due to the weak encryption used by PKCS#12, it is RECOMMENDED that you use the default password when encoding PKCS#12 files, and protect the PKCS#12 files using other means." default:"ChangeIt"`
	} `group:"PKI Options"`

	Logfile     string `long:"logfile" env:"LOGFILE" description:"Path to the Vaultbot logfile. Defaults to stdout."`
	RenewHook   string `long:"renew_hook" env:"RENEW_HOOK" description:"Command to execute after certificate has been updated. For this command, the shell environment variable VAULTBOT_RENEWED_CN will point to pki common name"`
	AutoConfirm bool   `short:"y" long:"auto_confirm" env:"AUTO_CONFIRM" description:"If set, user prompts will be auto confirmed with yes"`
	Version     bool   `long:"version" description:"Prints the current vaultbot version and exits."`
}
