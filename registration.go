package webauthn

import (
	"fmt"
	"time"
)

type RPConfig struct {
	ID              string
	Name            string
	Origins         []string
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
		RPID:             rp.RPConfig.ID,
		UserVerification: creationOptions.AuthenticatorSelection.UserVerification,
	}

	return creationOptions, session, nil
}

func (rp *RelyingParty) CreateCredential(session *Session, credential *RegistrationResponseJSON) (*CredentialRecord, error) {
	// Step 3. Let response be credential.response.
	// If response is not an instance of AuthenticatorAttestationResponse,
	// abort the ceremony with a user-visible error.
	authenticatorAttestationResponse, err := credential.Response.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// TODO: Step4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
	// clientExtensionResults := credential.GetClientExtensionResults()

	verifier, err := NewAuthenticatorAttestationResponseVerifeir(authenticatorAttestationResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation response verifier: %w", err)
	}

	// Step 7. Verify that the value of C.type is webauthn.create.
	if !verifier.IsValidCelemony() {
		return nil, fmt.Errorf("invalid ceremony, must be webauthn.create")
	}

	// Step 8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	if valid, err := verifier.VerifyChallenge(session.Challenge); !valid {
		return nil, fmt.Errorf("failed to verify challenge: %w", err)
	}

	// Step 9. Verify that the value of C.origin is an origin expected by the Relying Party.
	if valid, err := verifier.VerifyOrigin(rp.RPConfig.Origins, rp.RPConfig.SubFrameOrigins); !valid {
		return nil, fmt.Errorf("failed to validate origin: %w", err)
	}

	if valid, err := verifier.VerifyAuthenticatorData(rp.RPConfig.ID, session.UserVerification); !valid {
		return nil, fmt.Errorf("failed to validate authenticator data: %w", err)
	}

	// Step 26. Verify that the credentialId is not yet registered for any user.
	// If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.

	authenticatorData := verifier.AuthenticatorData()

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
