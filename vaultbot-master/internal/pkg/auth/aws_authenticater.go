package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/vault/api"

	"gitlab.com/msvechla/vaultbot/internal/pkg/cli"
)

const (
	// MethodAWSIAM authenticates to vault via AWS IAM Auth
	MethodAWSIAM = "aws-iam"

	// MethodAWSEC2 authenticates to vault via AWS EC2 Auth
	MethodAWSEC2 = "aws-ec2"

	// AWSAuthErrorMessage is the default error message for AWS IAM Authentication
	AWSAuthErrorMessage = "Error authenticating to vault via AWS IAM authentication"

	// AWSAuthHeaderKey is the header key used during AWS IAM authentication
	AWSAuthHeaderKey = "X-Vault-AWS-IAM-Server-ID"

	// NonceMaxBytes is the maximum number of bytes that will be read from the nonce file
	NonceMaxBytes = 1024
)

type AWSEC2Authenticater struct{}

// Authenticate to vault via the AWS authentication method
func (a *AWSEC2Authenticater) Authenticate(options cli.Options, client *api.Client) error {
	ec2m := ec2metadata.New(session.New())
	data, _ := ec2m.GetDynamicData("/instance-identity/pkcs7")

	loginData := make(map[string]interface{})
	var nonceFile *os.File
	writeNonce := false

	if options.Vault.AWSAuthNonce != "" && options.Vault.AWSAuthNoncePath != "" {
		return errors.Wrap(
			genericAuthError(options),
			"AWS EC2 Auth requires that only one of AWSAuthNonce, AWSAuthNoncePath is set",
		)
	}

	if options.Vault.AWSAuthNonce == "" {
		if options.Vault.AWSAuthNoncePath == "" {
			return errors.Wrap(
				genericAuthError(options),
				"AWS EC2 Auth requires one of the following arguments: AWSAuthNonce, AWSAuthNoncePath",
			)
		}
		// Attempt to read the nonce from file
		var nonce string
		nonce, nonceFile = readNonceFromFile(options)
		defer nonceFile.Close()

		if nonce == "" {
			writeNonce = true
		} else {
			loginData["nonce"] = nonce
		}
	} else {
		loginData["nonce"] = options.Vault.AWSAuthNonce
	}

	loginData["pkcs7"] = data
	loginData["role"] = options.Vault.AWSAuthRole

	// authenticate to vault
	resp, err := client.Logical().
		Write(fmt.Sprintf("auth/%s/login", options.Vault.AWSAuthMount), loginData)
	if err != nil {
		return errors.Wrap(genericAuthError(options), err.Error())
	}

	// retrieve the token
	var token string

	if token, err = resp.TokenID(); err != nil {
		return errors.Wrap(
			genericAuthError(options),
			"Error retrieving token after authentication to vault via AWS EC2 authentication: %s",
		)
	}

	if options.Vault.AWSAuthNoncePath != "" && writeNonce {
		var nonce interface{}
		var ok bool

		if metadata, metaErr := resp.TokenMetadata(); metaErr == nil {
			if nonce, ok = metadata["nonce"]; !ok {
				return errors.Wrap(
					genericAuthError(options),
					"Could not find AWS EC2 nonce from Vault's authentication response. Metadata: %v",
				)
			}
		} else {
			return errors.Wrap(genericAuthError(options), "Error retrieving token metadata after authentication to vault via AWS EC2 Auth: %s")
		}

		if nonceString, ok := nonce.(string); ok {
			_, writeErr := nonceFile.WriteString(nonceString)
			if writeErr != nil {
				return errors.Wrap(
					genericAuthError(options),
					"Unable to write nonce %s to file. Error: %s",
				)
			}

			err = nonceFile.Sync()
			if err != nil {
				return errors.Wrap(
					genericAuthError(options),
					"Unable to sync nonce file. Error: %s",
				)
			}
			log.Printf("Wrote nonce to file: %s", options.Vault.AWSAuthNoncePath)
		} else {
			return errors.Wrap(genericAuthError(options), "Could not convert AWS EC2 nonce in Vault's authentication response to string. Value was: %v")
		}
	}

	client.SetToken(token)
	return nil
}

type AWSIAMAuthenticater struct{}

// Authenticate to vault via AWS IAM authentication
func (a *AWSIAMAuthenticater) Authenticate(options cli.Options, client *api.Client) error {
	// construct sts session
	stsSession := session.New()

	var params *sts.GetCallerIdentityInput
	svc := sts.New(stsSession)
	stsRequest, _ := svc.GetCallerIdentityRequest(params)

	// ADD VAULT AWS IAM auth header value
	if options.Vault.AWSAuthHeader != "" {
		stsRequest.HTTPRequest.Header.Add(AWSAuthHeaderKey, options.Vault.AWSAuthHeader)
	}
	err := stsRequest.Sign()
	if err != nil {
		return errors.Wrap(genericAuthError(options), err.Error())
	}

	// Extract values from request
	headersJSON, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return errors.Wrap(genericAuthError(options), err.Error())
	}
	requestBody, err := io.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return errors.Wrap(genericAuthError(options), err.Error())
	}

	loginData := make(map[string]interface{})
	loginData["iam_http_request_method"] = stsRequest.HTTPRequest.Method
	loginData["iam_request_url"] = base64.StdEncoding.EncodeToString(
		[]byte(stsRequest.HTTPRequest.URL.String()),
	)
	loginData["iam_request_headers"] = base64.StdEncoding.EncodeToString(headersJSON)
	loginData["iam_request_body"] = base64.StdEncoding.EncodeToString(requestBody)
	loginData["role"] = options.Vault.AWSAuthRole

	// authenticate to vault
	resp, err := client.Logical().
		Write(fmt.Sprintf("auth/%s/login", options.Vault.AWSAuthMount), loginData)
	if err != nil {
		return errors.Wrap(genericAuthError(options), err.Error())
	}

	// retrieve the token
	var token string

	if token, err = resp.TokenID(); err != nil {
		return errors.Wrapf(
			genericAuthError(options),
			"Error retrieving token after authentication to vault via AWS IAM authentication: %s",
			err,
		)
	}

	client.SetToken(token)
	return nil
}

// readNonceFromFile attempts to read the nonce from a file.
// If the file does not exist yet, it will get created and it's file handle is returned.
func readNonceFromFile(options cli.Options) (string, *os.File) {
	if _, err := os.Stat(options.Vault.AWSAuthNoncePath); err == nil {
		nonceFile, openErr := os.OpenFile(options.Vault.AWSAuthNoncePath, os.O_RDONLY, 0)
		if openErr != nil {
			log.Fatalf("Error opening nonce file: %s", err)
		}

		// Read nonce
		nonceBytes := make([]byte, NonceMaxBytes)
		numRead, readErr := nonceFile.Read(nonceBytes)
		if readErr != nil {
			log.Fatalf("Error reading nonce from file: %s", err)
		}

		if numRead == 0 {
			log.Fatalf("Nonce length exceeded max length of %d bytes", NonceMaxBytes)
		}

		return string(nonceBytes[0:numRead]), nil
	} else if os.IsNotExist(err) {
		// If the nonce file does not exist yet, create it
		nonceFile, err := os.OpenFile(options.Vault.AWSAuthNoncePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0660)
		if err != nil {
			log.Fatalf("Could not create nonce file for writing. Will not attempt to authenticate to Vault via AWS EC2 Auth. Error: %s", err)
		}
		return "", nonceFile
	}
	return "", nil
}
