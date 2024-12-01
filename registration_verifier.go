package webauthn

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

type RegistrationCelemonyVerifier interface {
	VerifyChallenge(challenge []byte) (bool, error)
	VerifyOrigin(rpOrigins, rpSubFrameOrigins []string) (bool, error)
	VerifyRPID(rpID string) (bool, error)
	VerifyAuthenticatorDataFlags(userVerification UserVerification) (bool, error)
	VerifyPublicKeyAlgParams(params []PublicKeyCredentialParameters) (bool, error)
	VerifyAttestationStatement() (bool, error)

	AuthenticatorData() AuthenticatorData
	Response() AuthenticatorAttestationResponse
	ClientDataJSON() CollectedClientData
	AttestationObject() AttestationObject
}

type registrationCelemonyVerifier struct {
	response          AuthenticatorAttestationResponse
	clientDataJSON    CollectedClientData
	attestationObject AttestationObject
	authenticatorData AuthenticatorData
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

func (a *registrationCelemonyVerifier) VerifyChallenge(challenge []byte) (bool, error) {
	return a.clientDataJSON.VerifyChallenge(challenge)
}

func (a *registrationCelemonyVerifier) VerifyOrigin(rpOrigins, rpSubFrameOrigins []string) (bool, error) {
	return a.clientDataJSON.IsValidOrigin(rpOrigins, rpSubFrameOrigins)
}

func (a *registrationCelemonyVerifier) VerifyRPID(rpID string) (bool, error) {
	rpIDHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(a.authenticatorData.RPIDHash, rpIDHash[:]) {
		return false, fmt.Errorf("RP ID mismatch")
	}

	return true, nil
}

func (a *registrationCelemonyVerifier) VerifyAuthenticatorDataFlags(userVerification UserVerification) (bool, error) {
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

	return true, nil
}

func (a *registrationCelemonyVerifier) VerifyPublicKeyAlgParams(params []PublicKeyCredentialParameters) (bool, error) {
	// Step 19. Verify that the "alg" parameter in the credential public key in authData matches
	// the alg attribute of one of the items in `options.pubKeyCredParams``.
	if err := a.authenticatorData.AttestedCredentialData.VerifyPublicKeyAlgParams(params); err != nil {
		return false, fmt.Errorf("failed to verify public key algorithm: %w", err)
	}

	return true, nil
}

func (a *registrationCelemonyVerifier) VerifyAttestationStatement() (bool, error) {
	// Step 11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
	sum := sha256.Sum256(a.response.ClientDataJSON)
	hash := sum[:]
	// Step 21. Determine the attestation statement format by performing a USASCII case-sensitive match on
	// fmt against the set of supported WebAuthn Attestation Statement Format Identifier values.
	// An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is
	// maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
	stmtVerifier, err := DetermineAttestaionStatement(a.attestationObject.Format, a.attestationObject.AttStatement, a.attestationObject.AuthData, hash)
	if err != nil {
		return false, fmt.Errorf("failed to determine attestation statement: %w", err)
	}
	// Step 22. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature,
	// by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
	_, _, err = stmtVerifier.Verify()
	if err != nil {
		return false, fmt.Errorf("failed to verify attestation statement: %w", err)
	}

	// TODO: Step 23. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates)
	// for that attestation type and attestation statement format fmt, from a trusted source or from policy.
	// For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
	// using the aaguid in the attestedCredentialData in authData.

	// TODO: Step 24. Assess the attestation trustworthiness using the outputs of the verification procedure in step 21, as follows:

	return true, nil
}

func NewRegistrationCelemonyVerifier(registrationResponse RegistrationResponseJSON) (RegistrationCelemonyVerifier, error) {
	response, err := registrationResponse.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	return &registrationCelemonyVerifier{
		response:          response.Response,
		clientDataJSON:    response.ClientDataJSON,
		attestationObject: response.AttestationObject,
		authenticatorData: response.AuthenticatorData,
	}, nil
}
