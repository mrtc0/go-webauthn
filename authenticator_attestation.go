package webauthn

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorattestationresponsejson
type AuthenticatorAttestationResponseJSON struct {
	ClientDataJSON     string   `json:"clientDataJSON"`
	AuthenticatorData  string   `json:"authenticatorData"`
	Transports         []string `json:"transports"`
	PublicKey          string   `json:"publicKey"`
	PublicKeyAlgorithm int64    `json:"publicKeyAlgorithm"`
	AttestationObject  string   `json:"attestationObject"`
}

type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse

	AttestationObject AttestationObject

	rawAttestationObject []byte

	authenticatorData  AuthenticatorData
	transports         []string
	publicKey          string
	publicKeyAlgorithm int64
}

type registrationCelemonyVerifier struct {
	response          AuthenticatorAttestationResponse
	clientDataJSON    CollectedClientData
	attestationObject AttestationObject
	authenticatorData AuthenticatorData
}

type RegistrationCelemonyVerifier interface {
	VerifyCelemony() bool
	VerifyChallenge(challenge []byte) (bool, error)
	VerifyOrigin(rpOrigins, rpSubFrameOrigins []string) (bool, error)
	VerifyAuthenticatorData(rpID string, userVerification UserVerification) (bool, error)

	AuthenticatorData() AuthenticatorData
	Response() AuthenticatorAttestationResponse
	ClientDataJSON() CollectedClientData
	AttestationObject() AttestationObject
}

func (a registrationCelemonyVerifier) AuthenticatorData() AuthenticatorData {
	return a.authenticatorData
}

func (a registrationCelemonyVerifier) Response() AuthenticatorAttestationResponse {
	return a.response
}

func (a registrationCelemonyVerifier) ClientDataJSON() CollectedClientData {
	return a.clientDataJSON
}

func (a registrationCelemonyVerifier) AttestationObject() AttestationObject {
	return a.attestationObject
}

func (a AuthenticatorAttestationResponseJSON) Parse() (*AuthenticatorAttestationResponse, error) {
	rawAuthData, err := Base64URLEncodedByte(a.AuthenticatorData).Decode()
	if err != nil {
		return nil, err
	}

	authData := AuthenticatorData{}
	if err := authData.Unmarshal(rawAuthData); err != nil {
		return nil, err
	}

	authenticatorResponseJson := AuthenticatorResponseJSON{
		ClientDataJSON: a.ClientDataJSON,
	}
	authenticatorResponse, err := authenticatorResponseJson.Unmarshal()
	if err != nil {
		return nil, err
	}

	rawAttestationObject, err := Base64URLEncodedByte(a.AttestationObject).Decode()
	if err != nil {
		return nil, err
	}

	attestationObject := AttestationObject{}
	if err := cbor.Unmarshal(rawAttestationObject, &attestationObject); err != nil {
		return nil, err
	}

	return &AuthenticatorAttestationResponse{
		AuthenticatorResponse: *authenticatorResponse,
		AttestationObject:     attestationObject,
		rawAttestationObject:  rawAttestationObject,
		authenticatorData:     authData,
		transports:            a.Transports,
		publicKey:             a.PublicKey,
		publicKeyAlgorithm:    a.PublicKeyAlgorithm,
	}, nil
}

func (a *registrationCelemonyVerifier) VerifyCelemony() bool {
	return a.clientDataJSON.IsRegistrationCelemoney()
}

func (a *registrationCelemonyVerifier) VerifyChallenge(challenge []byte) (bool, error) {
	return a.clientDataJSON.VerifyChallenge(challenge)
}

func (a *registrationCelemonyVerifier) VerifyOrigin(rpOrigins, rpSubFrameOrigins []string) (bool, error) {
	return a.clientDataJSON.IsValidOrigin(rpOrigins, rpSubFrameOrigins)
}

func (a *registrationCelemonyVerifier) VerifyAuthenticatorData(rpID string, userVerification UserVerification) (bool, error) {
	// Step 11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
	sum := sha256.Sum256(a.response.ClientDataJSON)
	hash := sum[:]

	// Step 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	rpIDHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(a.authenticatorData.RPIDHash, rpIDHash[:]) {
		return false, fmt.Errorf("RP ID mismatch")
	}

	// Step 14. Verify that the UP bit of the flags in authData is set.
	if !a.authenticatorData.Flags.HasUserPresent() {
		return false, fmt.Errorf("UP bit not set")
	}

	// Step 15. If the Relying Party requires user verification for this registration, verify that the UV bit of the flags in authData is set.
	if userVerification.IsRequired() && !a.authenticatorData.Flags.HasUserVerified() {
		return false, fmt.Errorf("user verification required, but UV bit not set")
	}

	// Step 16. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
	if !a.authenticatorData.Flags.HasBackupEligible() && a.authenticatorData.Flags.HasBackupState() {
		return false, fmt.Errorf("BE bit not set, but BS bit set")
	}

	/*
		Steps 17 and 18 are performed by the RP for user experience and are not the responsibility of go-webauthn.
			Step 17. If the Relying Party uses the credential’s backup eligibility to inform its user experience flows and/or policies,
					 evaluate the BE bit of the flags in authData.
			Step 18. If the Relying Party uses the credential’s backup state to inform its user experience flows and/or policies,
					 evaluate the BS bit of the flags in authData.
	*/

	// Step 19. Verify that the "alg" parameter in the credential public key in authData matches
	// the alg attribute of one of the items in `options.pubKeyCredParams``.
	if err := a.authenticatorData.AttestedCredentialData.VerifyPublicKeyAlgParams(defaultCredentialParameters()); err != nil {
		return false, fmt.Errorf("failed to verify public key algorithm: %w", err)
	}

	// TODO: Step 20. Verify that the values of the client extension outputs in clientExtensionResults and
	// the authenticator extension outputs in the extensions in authData are as expected,
	// considering the client extension input values that were given in options.extensions and
	// any specific policy of the Relying Party regarding unsolicited extensions,
	// i.e., those that were not specified as part of options.extensions.
	// In the general case, the meaning of "are as expected" is specific to the Relying Party and
	// which extensions are in use.

	// Step 21. Determine the attestation statement format by performing a USASCII case-sensitive match on
	// fmt against the set of supported WebAuthn Attestation Statement Format Identifier values.
	// An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is
	// maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
	verifier, err := DetermineAttestaionStatement(a.attestationObject.Format, a.attestationObject.AttStatement, a.attestationObject.AuthData, hash)
	if err != nil {
		return false, fmt.Errorf("failed to determine attestation statement: %w", err)
	}
	// Step 22. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature,
	// by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
	_, _, err = verifier.Verify()
	if err != nil {
		return false, fmt.Errorf("failed to verify attestation statement: %w", err)
	}

	// TODO: Step 23. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates)
	// for that attestation type and attestation statement format fmt, from a trusted source or from policy.
	// For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
	// using the aaguid in the attestedCredentialData in authData.

	// TODO: Step 24. Assess the attestation trustworthiness using the outputs of the verification procedure in step 21, as follows:

	// Step 25. Verify that the credentialId is ≤ 1023 bytes.
	// Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
	if err := a.authenticatorData.AttestedCredentialData.VerifyCredentialID(); err != nil {
		return false, fmt.Errorf("failed to verify credential ID: %w", err)
	}

	return true, nil
}

func NewRegistrationCelemonyVerifier(registrationResponse RegistrationResponseJSON) (RegistrationCelemonyVerifier, error) {
	// Step 3. Let response be credential.response.
	// If response is not an instance of AuthenticatorAttestationResponse,
	// abort the ceremony with a user-visible error.
	response, err := registrationResponse.Response.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	c := response.GetParsedClientDataJSON()

	// Step 12. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
	attestationObject := response.AttestationObject
	authenticatorData := AuthenticatorData{}
	if err := authenticatorData.Unmarshal(attestationObject.AuthData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authenticator data: %w", err)
	}

	return &registrationCelemonyVerifier{
		response:          *response,
		clientDataJSON:    c,
		attestationObject: attestationObject,
		authenticatorData: authenticatorData,
	}, nil
}
