package webauthn

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type AuthenticationResponseJSON struct {
	PublicKeyCredential

	Response AuthenticatorAssertionResponseJSON `json:"response"`
}

// https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse
type AuthenticatorAssertionResponseJSON struct {
	AuthenticatorResponseJSON

	AuthenticatorData string  `json:"authenticatorData"`
	Signature         string  `json:"signature"`
	UserHandle        string  `json:"userHandle"`
	AttestationObject *string `json:"attestationObject"`
}

type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse

	AuthenticatorData *AuthenticatorData `json:"authenticatorData"`
	Signature         []byte             `json:"signature"`
	UserHandle        string             `json:"userHandle"`
	AttestationObject *AttestationObject `json:"attestationObject"`

	rawAuthData          []byte
	rawAttestationObject []byte
}

type SignCountEvaluater interface {
	EvaluateSignCount(requestSignCount uint32, currentSignCount uint32) (bool, error)
}

// DenyWhenClonedAuthenticator This is a SignCountEvaluater implementation that denies the request when the requestSignCount is greater than the currentSignCount.
func DenyWhenClonedAuthenticator(requestSignCount uint32, currentSignCount uint32) (bool, error) {
	if requestSignCount > currentSignCount {
		return true, nil
	}

	return false, nil
}

type authenticatorAssertionResponseVerifier struct {
	response         *AuthenticatorAssertionResponse
	credentialRecord *CredentialRecord
	clientDataJSON   *CollectedClientData

	signCountEvaluater SignCountEvaluater
}

type AuthenticatorAssertionResponseVerifier interface {
	IsAuthenticationCeremony() bool
	VerifyChallenge(challenge []byte) (bool, error)
	VerifyOrigin(rpOrigins, rpSubFrameOrigins []string) (bool, error)
	VerifyRPID(rpID string) bool
	VerifyUserPresent() bool
	VerifyUserVerified(userVerificationOption UserVerification) bool
	VerifyFlags() (bool, error)
	VerifySignature() (bool, error)
	EvaluateSignCount() (bool, error)
	VerifyAttestaionObject() (bool, error)
}

type AuthenticatorAssertionResponseVerifierOption func(*authenticatorAssertionResponseVerifier)

func WithSignCountEvaluater(evaluater SignCountEvaluater) AuthenticatorAssertionResponseVerifierOption {
	return func(v *authenticatorAssertionResponseVerifier) {
		v.signCountEvaluater = evaluater
	}
}

func NewAuthenticatorAssertionResponseVerifier(response *AuthenticatorAssertionResponse, credentialRecord *CredentialRecord, opts ...AuthenticatorAssertionResponseVerifierOption) *authenticatorAssertionResponseVerifier {
	c := response.GetParsedClientDataJSON()
	verifier := &authenticatorAssertionResponseVerifier{
		response:         response,
		credentialRecord: credentialRecord,
		clientDataJSON:   &c,
	}

	for _, opt := range opts {
		opt(verifier)
	}

	return verifier
}

func (a AuthenticatorAssertionResponseJSON) Parse() (*AuthenticatorAssertionResponse, error) {
	rawAuthData, err := Base64URLEncodedByte(a.AuthenticatorData).Decode()
	if err != nil {
		return nil, err
	}

	authData := &AuthenticatorData{}
	if err := authData.Unmarshal(rawAuthData); err != nil {
		return nil, err
	}

	userHandle, err := Base64URLEncodedByte(a.UserHandle).Decode()
	if err != nil {
		return nil, err
	}

	sig, err := Base64URLEncodedByte(a.Signature).Decode()
	if err != nil {
		return nil, err
	}

	var rawAttestationObject []byte
	var attestationObject *AttestationObject

	if a.AttestationObject != nil {
		rawAttestationObject, err = Base64URLEncodedByte(*a.AttestationObject).Decode()
		if err != nil {
			return nil, err
		}

		if err := cbor.Unmarshal(rawAttestationObject, &attestationObject); err != nil {
			return nil, err
		}
	}

	authenticatorResponse, err := a.AuthenticatorResponseJSON.Unmarshal()
	if err != nil {
		return nil, err
	}

	return &AuthenticatorAssertionResponse{
		AuthenticatorResponse: *authenticatorResponse,
		AuthenticatorData:     authData,
		Signature:             sig,
		UserHandle:            string(userHandle),
		AttestationObject:     attestationObject,
		rawAuthData:           rawAuthData,
		rawAttestationObject:  rawAttestationObject,
	}, nil
}

func (a *authenticatorAssertionResponseVerifier) IsAuthenticationCeremony() bool {
	return a.clientDataJSON.IsAuthenticationCeremony()
}

func (a *authenticatorAssertionResponseVerifier) VerifyChallenge(challenge []byte) (bool, error) {
	return a.clientDataJSON.VerifyChallenge(challenge)
}

func (a *authenticatorAssertionResponseVerifier) VerifyOrigin(rpOrigins, rpSubFrameOrigins []string) (bool, error) {
	return a.clientDataJSON.IsValidOrigin(rpOrigins, rpSubFrameOrigins)
}

func (a *authenticatorAssertionResponseVerifier) VerifyRPID(rpID string) bool {
	rpIDHash := sha256.Sum256([]byte(rpID))
	return bytes.Equal(a.response.AuthenticatorData.RPIDHash, rpIDHash[:])
}

func (a *authenticatorAssertionResponseVerifier) VerifyUserPresent() bool {
	return a.response.AuthenticatorData.Flags.HasUserPresent()
}

func (a *authenticatorAssertionResponseVerifier) VerifyUserVerified(userVerificationOption UserVerification) bool {
	if userVerificationOption.IsRequired() && !a.response.AuthenticatorData.Flags.HasUserVerified() {
		return false
	}

	return true
}

func (a *authenticatorAssertionResponseVerifier) VerifyFlags() (bool, error) {
	// Step 17. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
	if !a.response.AuthenticatorData.Flags.HasBackupEligible() && a.response.AuthenticatorData.Flags.HasBackupState() {
		return false, fmt.Errorf("BE bit is not set, but BS bit is set")
	}

	// Step 18. If the credential backup state is used as part of Relying Party business logic or policy,
	// let currentBe and currentBs be the values of the BE and BS bits, respectively, of the flags in authData.
	// Compare currentBe and currentBs with credentialRecord.backupEligible and credentialRecord.backupState:
	if a.credentialRecord.BackupEligible && !a.response.AuthenticatorData.Flags.HasBackupEligible() {
		return false, fmt.Errorf("backup eligible but BE bit is not set")
	}

	if !a.credentialRecord.BackupEligible && a.response.AuthenticatorData.Flags.HasBackupEligible() {
		return false, fmt.Errorf("not backup eligible but BE bit is set")
	}

	return true, nil
}

func (a *authenticatorAssertionResponseVerifier) VerifySignature() (bool, error) {
	// Step 20. Let hash be the result of computing a hash over the cData using SHA-256.
	cData := a.response.ClientDataJSON
	sum := sha256.Sum256([]byte(cData))
	hash := sum[:]

	rawAuthData := a.response.rawAuthData
	sig := a.response.Signature

	// Step 21. Using credentialRecord.publicKey, verify that sig is a valid signature over the
	// binary concatenation of authData and hash.
	publicKey, err := a.credentialRecord.GetPublicKey()
	if err != nil {
		return false, fmt.Errorf("failed to get public key: %w", err)
	}

	sigData := append(rawAuthData, hash...)
	valid, err := publicKey.Verify(sigData, sig)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %w", err)
	}

	if !valid {
		return false, fmt.Errorf("invalid signature")
	}

	return true, nil
}

func (a *authenticatorAssertionResponseVerifier) EvaluateSignCount() (bool, error) {
	// (Maybe) Authenticator does not implement signature counter
	if a.response.AuthenticatorData.SignCount == 0 || a.credentialRecord.SignCount == 0 {
		return true, nil
	}

	if a.signCountEvaluater == nil {
		return true, nil
	}

	return a.signCountEvaluater.EvaluateSignCount(a.response.AuthenticatorData.SignCount, a.credentialRecord.SignCount)
}

func (a *authenticatorAssertionResponseVerifier) VerifyAttestaionObject() (bool, error) {
	if a.response.AttestationObject == nil {
		return true, nil
	}

	if !a.response.AuthenticatorData.Flags.HasAttestedCredentialData() {
		return false, fmt.Errorf("attested credential data is not present")
	}

	authenticatorData := &AuthenticatorData{}
	if err := authenticatorData.Unmarshal(a.response.AttestationObject.AuthData); err != nil {
		return false, fmt.Errorf("failed to unmarshal authenticator data: %w", err)
	}

	credentialID := authenticatorData.AttestedCredentialData.CredentialID
	credentialPublicKey := authenticatorData.AttestedCredentialData.CredentialPublicKey
	if !bytes.Equal(credentialID, a.credentialRecord.ID) || !bytes.Equal(credentialPublicKey, a.credentialRecord.PublicKey) {
		return false, fmt.Errorf("credential mismatch")
	}

	cData := a.response.ClientDataJSON
	sum := sha256.Sum256([]byte(cData))
	hash := sum[:]

	verifier, err := DetermineAttestaionStatement(
		a.response.AttestationObject.Format,
		a.response.AttestationObject.AttStatement,
		a.response.rawAuthData,
		hash,
	)

	if err != nil {
		return false, err
	}

	_, _, err = verifier.Verify()
	if err != nil {
		return false, err
	}

	return true, nil
}
