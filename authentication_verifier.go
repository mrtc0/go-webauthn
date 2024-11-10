package webauthn

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

type AuthenticationCelemonyVerifier interface {
	IsAuthenticationCeremony() bool
	VerifyChallenge(challenge []byte) (bool, error)
	VerifyOrigin(rpOrigins, rpSubFrameOrigins []string) (bool, error)
	VerifyRPID(rpID string) bool
	VerifyUserPresent() bool
	VerifyUserVerified(userVerificationOption UserVerification) bool
	VerifyFlags() (bool, error)
	VerifySignature() (bool, error)
	VerifySignCount() (bool, error)
	VerifyAttestaionObject() (bool, error)

	GetUser() WebAuthnUser
	GetUserCredential() CredentialRecord
	GetAuthenticatorAssertionResponse() AuthenticatorAssertionResponse
	GetClientData() CollectedClientData
}

type authenticationCelemonyVerifier struct {
	publicKeyCredential PublicKeyCredential
	response            AuthenticatorAssertionResponse
	clientDataJSON      CollectedClientData

	user              WebAuthnUser
	userCredential    CredentialRecord
	signCountVerifier SignCountVerifier
}

func (a *authenticationCelemonyVerifier) GetUser() WebAuthnUser {
	return a.user
}

func (a *authenticationCelemonyVerifier) GetUserCredential() CredentialRecord {
	return a.userCredential
}

func (a *authenticationCelemonyVerifier) GetAuthenticatorAssertionResponse() AuthenticatorAssertionResponse {
	return a.response
}

func (a *authenticationCelemonyVerifier) GetClientData() CollectedClientData {
	return a.clientDataJSON
}

func (a *authenticationCelemonyVerifier) IsAuthenticationCeremony() bool {
	return a.clientDataJSON.IsAuthenticationCeremony()
}

func (a *authenticationCelemonyVerifier) VerifyChallenge(challenge []byte) (bool, error) {
	return a.clientDataJSON.VerifyChallenge(challenge)
}

func (a *authenticationCelemonyVerifier) VerifyOrigin(rpOrigins, rpSubFrameOrigins []string) (bool, error) {
	return a.clientDataJSON.IsValidOrigin(rpOrigins, rpSubFrameOrigins)
}

func (a *authenticationCelemonyVerifier) VerifyRPID(rpID string) bool {
	rpIDHash := sha256.Sum256([]byte(rpID))
	return bytes.Equal(a.response.AuthenticatorData.RPIDHash, rpIDHash[:])
}

func (a *authenticationCelemonyVerifier) VerifyUserPresent() bool {
	return a.response.AuthenticatorData.Flags.HasUserPresent()
}

func (a *authenticationCelemonyVerifier) VerifyUserVerified(userVerificationOption UserVerification) bool {
	if userVerificationOption.IsRequired() && !a.response.AuthenticatorData.Flags.HasUserVerified() {
		return false
	}

	return true
}

func (a *authenticationCelemonyVerifier) VerifyFlags() (bool, error) {
	// Step 17. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
	if !a.response.AuthenticatorData.Flags.HasBackupEligible() && a.response.AuthenticatorData.Flags.HasBackupState() {
		return false, fmt.Errorf("BE bit is not set, but BS bit is set")
	}

	// Step 18. If the credential backup state is used as part of Relying Party business logic or policy,
	// let currentBe and currentBs be the values of the BE and BS bits, respectively, of the flags in authData.
	// Compare currentBe and currentBs with credentialRecord.backupEligible and credentialRecord.backupState:
	if a.userCredential.BackupEligible && !a.response.AuthenticatorData.Flags.HasBackupEligible() {
		return false, fmt.Errorf("backup eligible but BE bit is not set")
	}

	if !a.userCredential.BackupEligible && a.response.AuthenticatorData.Flags.HasBackupEligible() {
		return false, fmt.Errorf("not backup eligible but BE bit is set")
	}

	return true, nil
}

func (a *authenticationCelemonyVerifier) VerifySignature() (bool, error) {
	// Step 20. Let hash be the result of computing a hash over the cData using SHA-256.
	cData := a.response.ClientDataJSON
	sum := sha256.Sum256([]byte(cData))
	hash := sum[:]

	rawAuthData := a.response.rawAuthData
	sig := a.response.Signature

	// Step 21. Using credentialRecord.publicKey, verify that sig is a valid signature over the
	// binary concatenation of authData and hash.
	publicKey, err := a.userCredential.GetPublicKey()
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

func (a *authenticationCelemonyVerifier) VerifySignCount() (bool, error) {
	if a.signCountVerifier == nil {
		return true, nil
	}

	return a.signCountVerifier(a.response.AuthenticatorData.SignCount, a.userCredential.SignCount)
}

func (a *authenticationCelemonyVerifier) VerifyAttestaionObject() (bool, error) {
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
	if !bytes.Equal(credentialID, a.userCredential.ID) || !bytes.Equal(credentialPublicKey, a.userCredential.PublicKey) {
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

type SignCountVerifier func(requestSignCount uint32, currentSignCount uint32) (bool, error)
type AuthenticatorAssertionResponseVerifierOption func(*authenticationCelemonyVerifier)
type DiscoveryUserHandler func(credentialRawID []byte, userHandle string) (*WebAuthnUser, *CredentialRecord, error)

func DenyWhenClonedAuthenticator(requestSignCount uint32, currentSignCount uint32) (bool, error) {
	// (Maybe) Authenticator does not implement signature counter
	if requestSignCount == 0 || currentSignCount == 0 {
		return true, nil
	}

	if requestSignCount > currentSignCount {
		return true, nil
	}

	return false, nil
}

func WithSignCountVerifier(verifier SignCountVerifier) AuthenticatorAssertionResponseVerifierOption {
	return func(v *authenticationCelemonyVerifier) {
		v.signCountVerifier = verifier
	}
}

func NewAuthenticationCelemonyVerifier(
	responseJSON AuthenticationResponseJSON,
	allowedCredentials []PublicKeyCredentialDescriptor,
	discoveryUserHandler DiscoveryUserHandler,
	opts ...AuthenticatorAssertionResponseVerifierOption,
) (AuthenticationCelemonyVerifier, error) {
	if discoveryUserHandler == nil {
		return nil, fmt.Errorf("discovery user handler is required")
	}

	// Step 3. Let response be credential.response.
	// If response is not an instance of AuthenticatorAssertionResponse,
	// abort the ceremony with a user-visible error.
	response, err := responseJSON.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// TODO: Step 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().

	// Step 5. If options.allowCredentials is not empty,
	// verify that credential.id identifies one of the public key credentials listed in
	// options.allowCredentials.
	if len(allowedCredentials) > 0 {
		found := false
		for _, allowedCredential := range allowedCredentials {
			if SecureCompareByte(allowedCredential.ID, response.PublicKeyCredential.ID) {
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("credential not allowed")
		}
	}

	// Step 6. Identify the user being authenticated and let credentialRecord be
	// the credential record for the credential:
	// If the user was identified before the authentication ceremony was initiated,
	// e.g., via a username or cookie, verify that the identified user account contains a credential record
	// whose id equals credential.rawId. Let credentialRecord be that credential record.
	// If response.userHandle is present, verify that it equals the user handle of the user account.
	// If the user was not identified before the authentication ceremony was initiated,
	// verify that response.userHandle is present. Verify that the user account identified
	// by response.userHandle contains a credential record whose id equals credential.rawId.
	// Let credentialRecord be that credential record.
	if response.Response.UserHandle == "" {
		return nil, fmt.Errorf("user handle is not present")
	}
	user, credentialRecord, err := discoveryUserHandler(
		response.PublicKeyCredential.RawID,
		response.Response.UserHandle)

	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if credentialRecord == nil || user == nil {
		return nil, fmt.Errorf("credential and user are required")
	}

	c := response.Response.GetParsedClientDataJSON()

	verifier := &authenticationCelemonyVerifier{
		publicKeyCredential: response.PublicKeyCredential,
		response:            response.Response,
		clientDataJSON:      c,

		user:              *user,
		userCredential:    *credentialRecord,
		signCountVerifier: DenyWhenClonedAuthenticator,
	}

	for _, opt := range opts {
		opt(verifier)
	}

	return verifier, nil
}
