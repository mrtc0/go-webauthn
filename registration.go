package webauthn

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type RP struct {
	ID              string
	Name            string
	Origin          string
	SubFrameOrigins []string
}

type WebAuthnUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []CredentialRecord
}

var defaultTimeout = (time.Second * 120).Milliseconds()

type RegistrationCeremonyOption func(*PublicKeyCredentialCreationOptions)

func WithAuthenticatorSelection(authenticatorSelectionCriteria AuthenticatorSelectionCriteria) RegistrationCeremonyOption {
	return func(options *PublicKeyCredentialCreationOptions) {
		options.AuthenticatorSelection = authenticatorSelectionCriteria
	}
}

func CreateOptionsForRegistrationCeremony(user *WebAuthnUser, RP *RP, opts ...RegistrationCeremonyOption) (*PublicKeyCredentialCreationOptions, *Session, error) {
	userEntity, err := newUserEntity(user.ID, user.Name, user.DisplayName)
	if err != nil {
		return nil, nil, err
	}

	publicKeyCredentialRPEntity := newPublicKeyCredentialRPEntity(RP.ID, RP.Name)

	challenge, err := GenerateChallenge()
	if err != nil {
		return nil, nil, err
	}

	creationOptions := &PublicKeyCredentialCreationOptions{
		RP:                     *publicKeyCredentialRPEntity,
		User:                   *userEntity,
		Challenge:              challenge,
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
		Challenge:        challenge.String(),
		RPID:             RP.Origin,
		UserID:           user.ID,
		UserVerification: "preferred",
	}

	return creationOptions, session, nil
}

func CreateCredential(user *WebAuthnUser, session *Session, credential *RegistrationResponseJSON, rp *RP) (*CredentialRecord, error) {
	if !bytes.Equal(user.ID, session.UserID) {
		return nil, errors.New("user ID mismatch")
	}

	// Step 3. Let response be credential.response. If response is not an instance of AuthenticatorAttestationResponse, abort the ceremony with a user-visible error.
	response, err := credential.Response.ToInstance()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// TODO: Step4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().

	// Step 5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
	// Step 6. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
	c, err := ParseClientDataJSON(response.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client data JSON: %w", err)
	}

	// Step 7. Verify that the value of C.type is webauthn.create.
	if !c.IsRegistrationCelemoney() {
		return nil, errors.New("invalid type. must be webauthn.create")
	}

	// Step 8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	if subtle.ConstantTimeCompare([]byte(c.Challenge), []byte(session.Challenge)) != 1 {
		return nil, errors.New("challenge mismatch")
	}

	// Step 9. Verify that the value of C.origin is an origin expected by the Relying Party. See § 13.4.9 Validating the origin of a credential for guidance.
	if _, err := url.ParseRequestURI(c.Origin); err != nil {
		return nil, fmt.Errorf("invalid origin: %w", err)
	}

	if c.Origin != rp.Origin {
		return nil, errors.New("origin mismatch")
	}

	// Step 10. If C.topOrigin is present:
	// 	1. Verify that the Relying Party expects that this credential would have been created within an iframe that is not same-origin with its ancestors.
	// 	2. Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within. See § 13.4.9 Validating the origin of a credential for guidance.
	if c.TopOrigin != "" {
		if !c.CrossOrigin {
			return nil, errors.New("topOrigin present but crossOrigin is false")
		}

		if len(rp.SubFrameOrigins) > 0 {
			if _, err := url.ParseRequestURI(c.TopOrigin); err != nil {
				return nil, fmt.Errorf("invalid top origin: %w", err)
			}

			found := false

			for _, subFrameOrigin := range rp.SubFrameOrigins {
				if c.TopOrigin == subFrameOrigin {
					found = true
					break
				}
			}

			if !found {
				return nil, errors.New("top origin mismatch")
			}
		}
	}

	// Step 11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
	sum := sha256.Sum256(response.ClientDataJSON)
	hash := sum[:]

	// Step 12. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
	attestationObjectData, err := response.AttestationObject.Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation object: %w", err)
	}

	var attestationObject AttestationObject
	if err := cbor.Unmarshal(attestationObjectData, &attestationObject); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation object: %w", err)
	}

	authenticatorData := &AuthenticatorData{}
	if err := authenticatorData.Unmarshal(attestationObject.AuthData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authenticator data: %w", err)
	}

	// Step 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	rpIDHash := sha256.Sum256([]byte(rp.ID))
	if !bytes.Equal(authenticatorData.RPIDHash, rpIDHash[:]) {
		return nil, errors.New("RP ID mismatch")
	}

	// Step 14. Verify that the UP bit of the flags in authData is set.
	if !authenticatorData.Flags.HasUserPresent() {
		return nil, errors.New("UP bit not set")
	}

	// Step 15. If the Relying Party requires user verification for this registration, verify that the UV bit of the flags in authData is set.
	if session.UserVerification == "required" && !authenticatorData.Flags.HasUserVerified() {
		return nil, errors.New("user verification required, but UV bit not set")
	}

	// Step 16. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
	if !authenticatorData.Flags.HasBackupEligible() && authenticatorData.Flags.HasBackupState() {
		return nil, errors.New("BE bit not set, but BS bit set")
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

	// TODO: Step 20. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.

	// Step 21. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
	verifier, err := DetermineAttestaionStatement(attestationObject.Format)
	if err != nil {
		return nil, fmt.Errorf("failed to determine attestation statement: %w", err)
	}
	// Step 22. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
	_, _, err = verifier.Verify()
	if err != nil {
		return nil, fmt.Errorf("failed to verify attestation statement: %w", err)
	}

	fmt.Printf("hash: %x\n", hash)
	// TODO: Step 23. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.
	// TODO: Step 24. Assess the attestation trustworthiness using the outputs of the verification procedure in step 21, as follows:
	// Step 25. Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
	if err := authenticatorData.AttestedCredentialData.VerifyCredentialID(); err != nil {
		return nil, fmt.Errorf("failed to verify credential ID: %w", err)
	}
	// Step 26. Verify that the credentialId is not yet registered for any user. If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.

	return &CredentialRecord{
		ID:                        authenticatorData.AttestedCredentialData.CredentialID,
		PublicKey:                 authenticatorData.AttestedCredentialData.CredentialPublicKey,
		SignCount:                 authenticatorData.SignCount,
		UvInitialized:             authenticatorData.Flags.HasUserVerified(),
		Transports:                []string{}, // TODO
		BackupEligible:            authenticatorData.Flags.HasBackupEligible(),
		BackupState:               authenticatorData.Flags.HasBackupState(),
		AttestationObject:         response.AttestationObject,
		AttestationClientDataJSON: response.ClientDataJSON,
	}, nil
}

func VerifyAuthenticatorAttestationResponse(response *AuthenticatorAttestationResponse, session *Session, rp *RP) error {
	return nil
}

func newUserEntity(id []byte, name, displayName string) (*PublicKeyCredentialUserEntity, error) {
	if len(id) > 64 || len(id) == 0 {
		return nil, errors.New("ID must be between 1 and 64 bytes")
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
