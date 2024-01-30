## [1.14.0](https://gitlab.com/msvechla/vaultbot/compare/v1.13.1...v1.14.0) (2024-1-15)


### Features

* add shell environment variable VAULTBOT_RENEWED_CN for renew hook ([f9e50da](https://gitlab.com/msvechla/vaultbot/commit/f9e50da816c4070b6654a488cf2f3bc2cb8c97b1))

## [1.13.1](https://gitlab.com/msvechla/vaultbot/compare/v1.13.0...v1.13.1) (2023-06-14)


### Bug Fixes

* **ci:** release ([eb9ce0e](https://gitlab.com/msvechla/vaultbot/commit/eb9ce0ec2944479dbebef6a5fca92d72af198c1b))
* **vaultbot:** remove extra space from pki_exclude_cn_from_sans so that flag will function as expected ([c7c9f4c](https://gitlab.com/msvechla/vaultbot/commit/c7c9f4c01334550e3293383c6e54fe838d6ce384))

## [1.13.2](https://gitlab.com/msvechla/vaultbot/compare/v1.13.1...v1.13.2) (2023-06-14)


### Bug Fixes

* **ci:** release ([eb9ce0e](https://gitlab.com/msvechla/vaultbot/commit/eb9ce0ec2944479dbebef6a5fca92d72af198c1b))

## [1.13.1](https://gitlab.com/msvechla/vaultbot/compare/v1.13.0...v1.13.1) (2023-06-13)


### Bug Fixes

* **vaultbot:** remove extra space from pki_exclude_cn_from_sans so that flag will function as expected ([c7c9f4c](https://gitlab.com/msvechla/vaultbot/commit/c7c9f4c01334550e3293383c6e54fe838d6ce384))

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.13.0] - 2022-04-22

### Added

- gcp and agent auth methods (see [!50](https://gitlab.com/msvechla/vaultbot/merge_requests/50), thanks a lot to [bhoriuchi](https://gitlab.com/bhoriuchi) for the MR 👏)

### Fixed

- fixed an issue where rpm / deb builds can have insecure permissions

## [1.12.0] - 2021-07-07

### Added

- switched to goreleaser for releasing artifacts
- `rpm` and `deb` builds

## [1.11.1] - 2021-04-05

### Fixed

- do not log error message when no logfile option has been specified (see [#38](https://gitlab.com/msvechla/vaultbot/issues/38))
- change default logfile permissions from `0666` to `0600`
- reduce token usage to 1 by only checking the authentication token when it is anyways not used in the current run  (see [#35](https://gitlab.com/msvechla/vaultbot/issues/35))

## [1.11.0] - 2021-03-14

### Fixed

- bumped golang to 1.16
- bumped module dependencies to latest minor version
- bumped vault/api to v1.0.5
- bigger internal refactoring to make code more habitable

## [1.10.1] - 2021-02-18

### Fixed

- incorrect parsing of PKCS12 umask (see [#33](https://gitlab.com/msvechla/vaultbot/issues/33))

## [1.10.0] - 2021-01-03

### Added

- bumped golang to 1.15
- added support for managing PKCS#12 certificates (see [#27](https://gitlab.com/msvechla/vaultbot/issues/27), thanks a lot to [DejfCold](https://gitlab.com/DejfCold) for the MR 👏)
- bumped docker base image to latest alpine

## [1.9.1] - 2020-07-05

### Added

- bumped golang to 1.14
- added multi-arch docker builds for arm64 (see [#29](https://gitlab.com/msvechla/vaultbot/issues/29))

## [1.9.0] - 2020-03-06

### Deprecated

- option `--pki_jks_export` will be removed in a future release. Determining certificate export to JKS is now done based on whether `--pki_jks_path` is specified

### Changed

- option `--pki_cert_path` no longer has any default value specified. This allows us to determine whether certificates should be exported to file, jks or both

### Added

- it is now possible to export certificates to either file, java key store or both. Whether certificates should be exported to either of those locations is determined based on wether the flags `--pki_cert_path` and / or `--pki_jks_path` have been specified (see [#28](https://gitlab.com/msvechla/vaultbot/issues/28))

## [1.8.3] - 2020-01-07

### Added

- logging of renew-hook output (see [#19](https://gitlab.com/msvechla/vaultbot/issues/19))
- docker image scanning in CI/CD pipeline using [snyk.io](https://snyk.io) (see [#25](https://gitlab.com/msvechla/vaultbot/issues/25))
- golang dependency scanning in CI/CD pipeline using [snyk.io](https://snyk.io) (see [#25](https://gitlab.com/msvechla/vaultbot/issues/25))

## [1.8.2] - 2020-01-02

### Fixed

- bumped go version to 1.13.5
- upgraded all dependencies to latest patch version to get the latest security and bug-fixes

## [1.8.1] - 2019-09-26

### Fixed

- fix typo which prevents env var `PKI_JKS_EXPORT` to work as expected (see [#17](https://gitlab.com/msvechla/vaultbot/issues/17))
- change naming of env variable `PKI_JKS_PRIVKEY_PATH` to `PKI_JKS_PRIVKEY_ALIAS`, which matches the corresponding CLI flag

## [1.8.0] - 2019-04-21

### Fixed

- build vaultbot based on go modules (see [#16](https://gitlab.com/msvechla/vaultbot/issues/16))

### Added

- allow specification of `pki_private_key_format` (PR by @zer0beat 👏)

## [1.7.0] - 2019-04-10

### Fixed

- PEM bundle file permissions are more strict now: `0600` (see [#12](https://gitlab.com/msvechla/vaultbot/issues/12))
- automated tests now work on branches of forks
- automated tests are now executed against `vault:1.1.0` and `go:1.12.1-stretch` (see [#11](https://gitlab.com/msvechla/vaultbot/issues/11))
- `CommonName` and `SAN` checks should not be case-sensitive (PR by @jflombardo 👏 & see [#13](https://gitlab.com/msvechla/vaultbot/issues/13))

### Added

- support for managing certificates in JAVA Keystores (PR by @jflombardo 👏)

## [1.6.0] - 2019-01-25

### Fixed

- correctly use supplied `ClientKey` option (PR by @fuerob 👏)

### Added

- `cert` authentication method (thanks @fuerob 👏)  

## [1.5.0] - 2018-12-23

### Added

- `approle` authentication method (see [#9](https://gitlab.com/msvechla/vaultbot/issues/9))  

## [1.4.0] - 2018-12-11

### Added

- `--version` flag to print current vaultbot version (see [#8](https://gitlab.com/msvechla/vaultbot/issues/8))

## [1.3.2] - 2018-12-10

### Fixed

- vaultbot falsely claimed that certificate data changed on certificates with empty dns- and ip sans (see [#7](https://gitlab.com/msvechla/vaultbot/issues/7))

### Added

- test with empty dns- and up sans on the to-be-updated certificate

## [1.3.1] - 2018-11-11

### Fixed

- write AWS EC2 Auth nonce to file, if it has not been set via CLI flag. Based on PR by @eljas 👏
- correct vault version output on startup

## [1.3.0] - 2018-11-04

### Added

- support for vault `AWS EC2` and `AWS IAM` authentication (see [#4](https://gitlab.com/msvechla/vaultbot/issues/4))
- introduced `go mod`
- first refactoring into packages to improve maintainability

## [1.2.2] - 2018-09-18

### Fixed

- renamed incorrect environment variable names for `PKI_COMMON_NAME` and `PKI_RENEW_PERCENT`. PR by @fuerob 👏
- markdown lint errors in CHANGELOG.md

## [1.2.1] - 2018-04-11

### Fixed

- error handling for parsing certificates
- bumped to latest go version

## [1.2.0] - 2018-03-12

### Added

- `pem_bundle` option, to specify an output location of the certificate chain and private key as PEM bundle

## [1.1.0] - 2018-01-24

### Added

- Use `renew_hook` to specify a command which will be executed after a successful certificate renewal
- JSON logging using [logrus](https://github.com/sirupsen/logrus)
- Logging to file by specifying the `logfile` option

## [1.0.2] - 2018-01-23

### Fixed

- Fixed initial cert request not working as expected

### Added

- End to end tests to catch obvious errors
- CA-Certificates to docker image
- Push all docker tags according to SemVer

## [1.0.1] - 2018-01-22

### Fixed

- Fixed build pipeline for all major platforms

## [1.0.0] - 2018-01-21

### Added

- Initial version release
- Request new certificates
- Expiry checks by percent and fixed time
- Sanity checks before overwriting files
- Complete tests with vault in Docker
- CI Pipeline
- README
- CHANGELOG
- ...
