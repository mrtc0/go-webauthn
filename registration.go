package webauthn

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"
)

type RPConfig struct {
	ID              string
	Name            string
	Origin          string
	SubFrameOrigins []string
}

type RelyingParty struct {
	RPConfig *RPConfig
}

type WebAuthnUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []CredentialRecord
}

var defaultTimeout = (time.Second * 120).Milliseconds()

func NewRelyingParty(rp *RPConfig) *RelyingParty {
	return &RelyingParty{RPConfig: rp}
}

type RegistrationCeremonyOption func(*PublicKeyCredentialCreationOptions)

func WithAuthenticatorSelection(authenticatorSelectionCriteria AuthenticatorSelectionCriteria) RegistrationCeremonyOption {
	return func(options *PublicKeyCredentialCreationOptions) {
		options.AuthenticatorSelection = authenticatorSelectionCriteria
	}
}

func (rp *RelyingParty) CreateOptionsForRegistrationCeremony(user *WebAuthnUser, opts ...RegistrationCeremonyOption) (*PublicKeyCredentialCreationOptions, *Session, error) {
	userEntity, err := newUserEntity(user.ID, user.Name, user.DisplayName)
	if err != nil {
		return nil, nil, err
	}

	publicKeyCredentialRPEntity := newPublicKeyCredentialRPEntity(rp.RPConfig.ID, rp.RPConfig.Name)

	challenge, err := GenerateChallenge()
	if err != nil {
		return nil, nil, err
	}

	creationOptions := &PublicKeyCredentialCreationOptions{
		RP:                     *publicKeyCredentialRPEntity,
		User:                   *userEntity,
		Challenge:              Base64URLEncodedByte(challenge),
		PubKeyCredParams:       defaultCredentialParameters(),
		Timeout:                defaultTimeout,
		ExcludeCredentials:     []PublicKeyCredentialDescriptor{},
		AuthenticatorSelection: AuthenticatorSelectionCriteria{},
		Attestation:            "none",
	}

	for _, opt := range opts {
		opt(creationOptions)
	}

	session := &Session{
		ID:               user.ID,
		Challenge:        challenge,
		RPID:             rp.RPConfig.Origin,
		UserVerification: creationOptions.AuthenticatorSelection.UserVerification,
	}

	return creationOptions, session, nil
}

func (rp *RelyingParty) CreateCredential(session *Session, credential *RegistrationResponseJSON) (*CredentialRecord, error) {
	// Step 3. Let response be credential.response.
	// If response is not an instance of AuthenticatorAttestationResponse,
	// abort the ceremony with a user-visible error.
	authenticatorAttestationResponse, err := credential.Response.Unmarshal()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// TODO: Step4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
	// clientExtensionResults := credential.GetClientExtensionResults()

	// Step 5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
	// Step 6. Let C, the client data claimed as collected during the credential creation,
	// be the result of running an implementation-specific JSON parser on JSONtext.
	c := authenticatorAttestationResponse.GetParsedClientDataJSON()

	// Step 7. Verify that the value of C.type is webauthn.create.
	if !c.IsRegistrationCelemoney() {
		return nil, fmt.Errorf("invalid type. must be webauthn.create")
	}

	// Step 8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	challenge, err := Base64URLEncodedByte(c.Challenge).Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode challenge: %w", err)
	}

	if !SecureCompareByte(challenge, session.Challenge) {
		return nil, fmt.Errorf("challenge mismatch")
	}

	// Step 9. Verify that the value of C.origin is an origin expected by the Relying Party.
	// See § 13.4.9 Validating the origin of a credential for guidance.
	// from § 13.4.9:
	// 	> When registering a credential and when verifying an assertion,
	// 	> the Relying Party MUST validate the origin member of the client data.
	// 	> The Relying Party MUST NOT accept unexpected values of origin,
	// 	> as doing so could allow a malicious website to obtain valid credentials
	// Origin can be a case like https://example.com or a native app example-os:appid:...
	if c.Origin != rp.RPConfig.Origin {
		return nil, fmt.Errorf("origin mismatch")
	}

	// Step 10. If C.topOrigin is present:
	// 	1. Verify that the Relying Party expects that this credential would have been created within an iframe that is not same-origin with its ancestors.
	// 	2. Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within. See § 13.4.9 Validating the origin of a credential for guidance.
	// ref. https://www.w3.org/TR/webauthn-3/#sctn-validating-origin
	if c.TopOrigin != "" {
		if !c.CrossOrigin {
			return nil, fmt.Errorf("topOrigin present but crossOrigin is false")
		}

		if len(rp.RPConfig.SubFrameOrigins) > 0 {
			found := false

			for _, subFrameOrigin := range rp.RPConfig.SubFrameOrigins {
				if c.TopOrigin == subFrameOrigin {
					found = true
					break
				}
			}

			if !found {
				return nil, fmt.Errorf("top origin mismatch")
			}
		}
	}

	// Step 11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
	sum := sha256.Sum256(authenticatorAttestationResponse.ClientDataJSON)
	hash := sum[:]

	// Step 12. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
	attestationObject := authenticatorAttestationResponse.AttestationObject
	authenticatorData := &AuthenticatorData{}
	if err := authenticatorData.Unmarshal(attestationObject.AuthData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authenticator data: %w", err)
	}

	// Step 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	rpIDHash := sha256.Sum256([]byte(rp.RPConfig.ID))
	if !bytes.Equal(authenticatorData.RPIDHash, rpIDHash[:]) {
		return nil, fmt.Errorf("RP ID mismatch")
	}

	// Step 14. Verify that the UP bit of the flags in authData is set.
	if !authenticatorData.Flags.HasUserPresent() {
		return nil, fmt.Errorf("UP bit not set")
	}

	// Step 15. If the Relying Party requires user verification for this registration, verify that the UV bit of the flags in authData is set.
	if session.UserVerification.IsRequired() && !authenticatorData.Flags.HasUserVerified() {
		return nil, fmt.Errorf("user verification required, but UV bit not set")
	}

	// Step 16. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
	if !authenticatorData.Flags.HasBackupEligible() && authenticatorData.Flags.HasBackupState() {
		return nil, fmt.Errorf("BE bit not set, but BS bit set")
	}

	/*
		Steps 17 and 18 are performed by the RP for user experience and are not the responsibility of go-webauthn.
			Step 17. If the Relying Party uses the credential’s backup eligibility to inform its user experience flows and/or policies,
					 evaluate the BE bit of the flags in authData.
			Step 18. If the Relying Party uses the credential’s backup state to inform its user experience flows and/or policies,
					 evaluate the BS bit of the flags in authData.
	*/

	// Step 19. Verify that the "alg" parameter in the credential public key in authData matches
	// 			the alg attribute of one of the items in `options.pubKeyCredParams``.
	if err := authenticatorData.AttestedCredentialData.VerifyPublicKeyAlgParams(defaultCredentialParameters()); err != nil {
		return nil, fmt.Errorf("failed to verify public key algorithm: %w", err)
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
	verifier, err := DetermineAttestaionStatement(attestationObject.Format, attestationObject.AttStatement, attestationObject.AuthData, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to determine attestation statement: %w", err)
	}
	// Step 22. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature,
	// by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
	_, _, err = verifier.Verify()
	if err != nil {
		return nil, fmt.Errorf("failed to verify attestation statement: %w", err)
	}

	// TODO: Step 23. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates)
	// for that attestation type and attestation statement format fmt, from a trusted source or from policy.
	// For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
	// using the aaguid in the attestedCredentialData in authData.

	// TODO: Step 24. Assess the attestation trustworthiness using the outputs of the verification procedure in step 21, as follows:

	// Step 25. Verify that the credentialId is ≤ 1023 bytes.
	// Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
	if err := authenticatorData.AttestedCredentialData.VerifyCredentialID(); err != nil {
		return nil, fmt.Errorf("failed to verify credential ID: %w", err)
	}
	// Step 26. Verify that the credentialId is not yet registered for any user.
	// If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.

	return &CredentialRecord{
		ID:                        authenticatorData.AttestedCredentialData.CredentialID,
		PublicKey:                 authenticatorData.AttestedCredentialData.CredentialPublicKey,
		SignCount:                 authenticatorData.SignCount,
		UvInitialized:             authenticatorData.Flags.HasUserVerified(),
		Transports:                authenticatorAttestationResponse.transports,
		BackupEligible:            authenticatorData.Flags.HasBackupEligible(),
		BackupState:               authenticatorData.Flags.HasBackupState(),
		AttestationObject:         authenticatorAttestationResponse.rawAttestationObject,
		AttestationClientDataJSON: authenticatorAttestationResponse.ClientDataJSON,
	}, nil
}

func VerifyAuthenticatorAttestationResponse(response *AuthenticatorAttestationResponse, session *Session, rp *RPConfig) error {
	return nil
}

func newUserEntity(id []byte, name, displayName string) (*PublicKeyCredentialUserEntity, error) {
	if len(id) > 64 || len(id) == 0 {
		return nil, fmt.Errorf("ID must be between 1 and 64 bytes")
	}

	return &PublicKeyCredentialUserEntity{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
	}, nil
}

func newPublicKeyCredentialRPEntity(id, name string) *PublicKeyCredentialRpEntity {
	return &PublicKeyCredentialRpEntity{
		ID: id,
		PublicKeyCredentialEntity: PublicKeyCredentialEntity{
			Name: name,
		},
	}
}
