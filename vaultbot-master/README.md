[![pipeline status](https://gitlab.com/msvechla/vaultbot/badges/master/pipeline.svg)](https://gitlab.com/msvechla/vaultbot/commits/master) [![coverage report](https://gitlab.com/msvechla/vaultbot/badges/master/coverage.svg)](https://gitlab.com/msvechla/vaultbot/commits/master) [![Go Report Card](https://goreportcard.com/badge/gitlab.com/msvechla/vaultbot)](https://goreportcard.com/report/gitlab.com/msvechla/vaultbot) [![Docker Pulls](https://badgen.net/docker/pulls/msvechla/vaultbot)](https://hub.docker.com/r/msvechla/vaultbot)

# Vaultbot

![vaultbot](./vaultbot.png "vaultbot")

Lightweight [Hashicorp Vault](https://www.vaultproject.io/) PKI client, built for infrastructure automation. Automatically request and renew certificates generated inside vault via the [PKI backend](https://www.vaultproject.io/docs/secrets/pki/index.html).

By default, Vaultbot will only renew certificates that are due for renewal within a specified period. Therefore Vaultbot is ideal for running at a fixed interval (e.g. crontab). This tool is also inspired by the well-known [certbot](https://github.com/certbot/certbot) for letsencrypt.

[[_TOC_]]

## Getting Started

Requesting and renewing a certificate is straightforward. See the following self-explanatory example:

```sh
./vaultbot --vault_addr=http://localhost:1234 --vault_token=myroot --pki_mount=pki --pki_role_name=example-dot-com  --pki_common_name=mydomain.com --pki_ttl=24h --pki_renew_time=4h --pki_alt_names=otherdomain.com,testing.com --pki_ip_sans=127.0.0.1
```

You can also see further usage information by running `./vaultbot --help`

### Get the latest release

#### Container Image

The [Docker Image](https://hub.docker.com/r/msvechla/vaultbot/) is published on Dockerhub and is scanned for vulnerabilites beforehand.

Tags are published in the following form:

```
${MAJOR}
${MAJOR}.${MINOR}
${MAJOR}.${MINOR}.${PATCH}
```

#### Binary Releases

Automated builds are available for all major platforms. All [releases](https://gitlab.com/msvechla/vaultbot/-/releases) are scanned for vulnearbilities before publishing.

Alternatively, you can build the latest version from source as well.

## Configuration

You can configure Vaultbot by specifying command-line options or the corresponding environment variables.

```text
Usage:
  vaultbot [OPTIONS]

Application Options:
  -v, --verbose                               Show verbose debug information
      --logfile=                              Path to the Vaultbot logfile. Defaults to stdout. [$LOGFILE]
      --renew_hook=                           Command to execute after certificate has been updated. For this command, the shell environment variable VAULTBOT_RENEWED_CN will point to pki common name [$RENEW_HOOK]
  -y, --auto_confirm                          If set, user prompts will be auto confirmed with yes [$AUTO_CONFIRM]
      --version                               Prints the current vaultbot version and exits.

Vault Options:
      --vault_addr=                           The address of the Vault server expressed as a URL and port (default: http://127.0.0.1:8200) [$VAULT_ADDR]
      --vault_cacert=                         Path to a PEM-encoded CA cert file to use to verify the Vault server SSL certificate. [$VAULT_CACERT]
      --vault_capath=                         Path to a directory of PEM-encoded CA cert files to verify the Vault server SSL certificate. If VAULT_CACERT is specified, its value will take precedence. [$VAULT_CAPATH]
      --vault_client_cert=                    Path to a PEM-encoded client certificate for TLS authentication to the Vault server. [$VAULT_CLIENT_CERT]
      --vault_client_key=                     Path to an unencrypted PEM-encoded private key matching the client certificate. [$VAULT_CLIENT_KEY]
      --vault_client_timeout=                 Timeout variable for the vault client. [$VAULT_CLIENT_TIMEOUT]
      --vault_skip_verify                     If set, do not verify Vault's presented certificate before communicating with it. Setting this variable is not recommended except during testing. [$VAULT_SKIP_VERIFY]
      --vault_tls_server_name=                If set, use the given name as the SNI host when connecting via TLS. [$VAULT_TLS_SERVER_NAME]
      --vault_max_retries=                    The maximum number of retries when a 5xx error code is encountered. [$VAULT_MAX_RETRIES]
      --vault_token=                          The Vault authentication token. [$VAULT_TOKEN]
      --vault_renew_token                     If set, vaultbot tries to automatically renew the current token [$RENEW_TOKEN]
      --vault_auth_method=                    The method used to authenitcate to vault. Should be one of [agent, cert, approle, token, aws-iam, aws-ec2, gcp-gce, gcp-iam] (default: token) [$VAULT_AUTH_METHOD]
      --vault_certificate_role=               The certificate role to authenticate against, when using the cert auth mehtod. [$VAULT_CERTIFICATE_ROLE]
      --vault_aws_auth_role=                  The role to use for AWS IAM authentication [$VAULT_AWS_AUTH_ROLE]
      --vault_aws_auth_mount=                 The mount path for the vault AWS auth method (default: aws) [$VAULT_AWS_AUTH_MOUNT]
      --vault_aws_auth_header=                The header to use during vault AWS IAM authentication. If empty no header will be set [$VAULT_AWS_AUTH_HEADER]
      --vault_aws_auth_nonce=                 The nonce to use during vault AWS EC2 authentication [$VAULT_AWS_AUTH_NONCE]
      --vault_aws_auth_nonce_path=            If set, the nonce that is used during vault AWS EC2 authentication will be written to this path [$VAULT_AWS_AUTH_NONCE_PATH]
      --vault_gcp_auth_role=                  The role to use for GCP authentication [$VAULT_GCP_AUTH_ROLE]
      --vault_gcp_auth_service_account_email= The service account email to use for GCP IAM authentiation [$VAULT_GCP_AUTH_SERVICE_ACCOUNT_EMAIL]
      --vault_gcp_auth_mount=                 The mount path for the vault GCP auth method (default: gcp) [$VAULT_GCP_AUTH_MOUNT]
      --vault_app_role_mount=                 The mount path for the AppRole backend (default: approle) [$VAULT_APP_ROLE_MOUNT]
      --vault_app_role_role_id=               RoleID of the AppRole [$VAULT_APP_ROLE_ROLE_ID]
      --vault_app_role_secret_id=             SecretID belonging to AppRole [$VAULT_APP_ROLE_SECRET_ID]

PKI Options:
      --pki_mount=                            Specifies the PKI backend mount path (default: pki) [$PKI_MOUNT]
      --pki_role_name=                        Specifies the name of the role to create the certificate against [$PKI_ROLE_NAME]
      --pki_common_name=                      Specifies the requested CN for the certificate [$PKI_COMMON_NAME]
      --pki_alt_names=                        Specifies requested Subject Alternative Names, in a comma-delimited list [$PKI_ALT_NAMES]
      --pki_ip_sans=                          Specifies requested IP Subject Alternative Names, in a comma-delimited list [$PKI_IP_SANS]
      --pki_ttl=                              Specifies requested Time To Live [$PKI_TTL]
      --pki_exclude_cn_from_sans              If set, the given common_name will not be included in DNS or Email Subject Alternate Names (as appropriate) [$EXCLUDE_CN_FROM_SANS]
      --pki_private_key_format=               Specifies the format for marshaling the private key. [$PRIVATE_KEY_FORMAT]
      --pki_renew_percent=                    Percentage of requested certificate TTL, which triggers a renewal when passed (>0.00, <1.00) (default: 0.75) [$PKI_RENEW_PERCENT]
      --pki_renew_time=                       Time in hours before certificate expiry, which triggers a renewal (e.g. 12h, 1m). Takes precedence over renew_time when set. [$PKI_RENEW_TIME]
      --pki_force_renew                       If set, the certificate will be renewed without checking the expiry [$PKI_FORCE_RENEW]
      --pki_cert_path=                        Path to the requested / to be updated certificate [$PKI_CERT_PATH]
      --pki_cachain_path=                     Path to the CA Chain of the requested / to be updated certificate (default: chain.pem) [$PKI_CACHAIN_PATH]
      --pki_privkey_path=                     Path to the private key of the requested / to be updated certificate (default: key.pem) [$PKI_PRIVKEY_PATH]
      --pki_pembundle_path=                   Path to the pem bundle of the requested / to be updated certificate, private key and ca chain [$PKI_PEMBUNDLE_PATH]
      --pki_jks_export                        DEPRECATED: export to JKS is now determined by specifying pki_jks_path [$PKI_JKS_EXPORT]
      --pki_jks_path=                         Path to a JAVA KeyStore where the certificates should be exported [$PKI_JKS_PATH]
      --pki_jks_password=                     JAVA KeyStore password (default: ChangeIt) [$PKI_JKS_PASSWORD]
      --pki_jks_cert_alias=                   Alias in the JAVA KeyStore of the requested / to be updated certificate (default: cert.pem) [$PKI_JKS_CERT_ALIAS]
      --pki_jks_cachain_alias=                Alias in the JAVA KeyStore of the CA Chain of the requested / to be updated certificate (default: chain.pem) [$PKI_JKS_CACHAIN_ALIAS]
      --pki_jks_privkey_alias=                Alias in the JAVA KeyStore of the private key of the requested / to be updated certificate (default: key.pem) [$PKI_JKS_PRIVKEY_ALIAS]
      --pki_pkcs12_path=                      Path to a PKCS#12 KeyStore where the certificates should be exported to [$PKI_PKCS12_PATH]
      --pki_pkcs12_umask=                     Umask of the generated PKCS#12 KeyStore. Existing keystore will keep it's umask. Octal format required (e.g. 0644) (default: 0600) [$PKI_PKCS12_UMASK]
      --pki_pkcs12_password=                  Default password is "ChangeIt", a commonly-used password for PKCS#12 files. Due to the weak encryption used by PKCS#12, it is RECOMMENDED that you use the default password when encoding PKCS#12 files, and protect the PKCS#12 files using other means. (default: ChangeIt) [$PKI_PKCS12_PASSWORD]

Help Options:
  -h, --help                                  Show this help message
```

## Renewing existing certificates

When Vaultbot is run and `pki_cert_path` points to an existing certificate, the certificate is only renewed and overwritten when specific criteria are met.

You can either specify `pki_renew_percent` (e.g. 0.75), to renew the certificate after 75% of its lifespan has been reached. Otherwise, you can specify `pki_renew_time` to set a fixed amount of time before the expiry date, which will trigger a renewal when passed.

If you want to renew the certificate on every run, you can specify the `pki_force_renew` flag.

## Renew Hook

Vaultbot can execute arbitrary commands after a successful certificate renewal, by specifying the `renew_hook` flag.

## Sanity checks and user confirmation

By default, Vaultbot performs a small set of sanity checks before overwriting an existing certificate at the `pki_(cert/cachain/privkey/_path)` locations.

If the newly requested certificate data (common name, dns alternative names, ip SANS) differs from the data specified in the existing certificate at the location, the user will be asked for confirmation.

If you want to skip these checks in automated environments, you can specify the `y` or  `auto_confirm` flag.

## Authentication Methods

Vaultbot supports the following methods to authenticate to vault. These methods can be configured via the `vault_auth_method` option. For more information see [Configuration](#Configuration).

| Authentication Option | Description                                                                                                                                      |
|-----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `agent`               | Authentication through an [auto-auth](https://www.vaultproject.io/docs/agent/autoauth) configured [vault agent](https://www.vaultproject.io/docs/agent). Requires the vault_addr to point to the configured vault agent |
| `token`               | Simple method where only a token is supplied, see [vault token auth](https://www.vaultproject.io/docs/auth/token.html)                           |
| `cert`                | Authentication via TLS client certificate, see [vault cert auth](https://www.vaultproject.io/docs/auth/cert.html)                                |
| `approle`             | Authentication method designed for automated / non-human operators, see [vault AppRole auth](https://www.vaultproject.io/docs/auth/approle.html) |
| `aws-iam`             | Authentication via AWS IAM credentials, see [vault IAM auth](https://www.vaultproject.io/docs/auth/aws.html#iam-auth-method)                     |
| `aws-ec2`             | Authentication via AWS EC2 metadata, see [vault ec2 auth](https://www.vaultproject.io/docs/auth/aws.html#ec2-auth-method)                        |
| `gcp-iam`             | Authentication via GCP IAM metadata, see [vault gcp auth](https://www.vaultproject.io/docs/auth/gcp)                                                                                      |
| `gcp-gce`             | Authentication via GCP GCE metadata, see [vault gcp auth](https://www.vaultproject.io/docs/auth/gcp)                                                                                      |
## Managing JAVA Key Store

By default, Vaultbot manages certificates through PEM files. In some ecosystems, certificates and keys might be stored within JAVA Key Stores.

To check, store, and renew certificates and keys from JAVA Key Stores, specify the `--pki_jks_path` parameter. Provide the path and matching password to the keystore via `--pki_jks_path=path/to/my/jks.jks` and `--pki_jks_password=My53cr3t`. All keys and certificates can then be differentiated thanks to their JAVA Key Store aliases:
`--pki_jks_cert_alias=MyCertAlias -pki_jks_cachain_alias=MyCAChainAlias --pki_jks_privkey_alias=MyPrivKeyAlias`

All other functionality is identical to the regular Vaulbot behavior. Please note that certificates and keys will be exported to to both PEM files and JAVA Key Stores if both `--pki_jks_path` and `--pki_cert_path` are specified.

> WARNING: Please keep in mind that this functionality relies on the external community mod [pavel-v-chernykh/keystore-go](https://github.com/pavel-v-chernykh/keystore-go). We recommend using a new Keystore specifically for Vaultbot, to avoid unforeseen changes to existing Keystores.

## Managing PKCS#12 Key Store

By default, Vaultbot manages certificates through PEM files. In some ecosystems, certificates and keys might be stored within PKCS#12 Key Stores.

To check, store, and renew certificates and keys from PKCS#12 Key Stores, specifiy the `--pki_pkcs12_path` parameter. Provide the path and matching password to the keystore via `--pki_pkcs12_path=path/to/my/pfx.p12` and `--pki_pkcs12_password=ChangeIt`. Optionaly provide umask using`--pki_pkcs12_umask` and the octal syntax (e.g. 0644)

All other functionality is identical to the regular Vaulbot behavior. Please note that certififcates and keys will be exported to both PEM files and PKCS#12 Key Stores if both `--pki_pkcs12_path` and `--pki_cert_path` are specified.

> WARNING: This functionality as of now doesn't support friendly names

## Production Use cases and Users

*If you are using **vaultbot** in a production environment, let us know by creating a MR and adding yourself to the list. It's always awesome to see a project put to good use 🚀*

Use cases of vaultbot:

- continuously renewing short-lived certificates for 50+ elasticsearch nodes [@share-now](https://www.share-now.com/)

## Contributing

Please read [CONTRIBUTING.md]() for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://gitlab.com/msvechla/kubehiera/tags) or take a look at the [CHANGELOG.md](./CHANGELOG.md)

## Authors

- **Marius Svechla** - *Initial work*

See also the list of [contributors](https://gitlab.com/msvechla/vaultbot/-/graphs/master) who participated in this project.

## License

[MIT License](./LICENSE.md)  
Copyright (c) [2018] [Marius Svechla]

## Acknowledgments

- The official [vault go client](https://github.com/hashicorp/vault/tree/master/api)
