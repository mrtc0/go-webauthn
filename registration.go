package webauthn

import (
	"fmt"
)

var (
	defaultAuthenticatorSelection = AuthenticatorSelectionCriteria{
		RequireResidentKey: true,
		ResidentKey:        "required",
		// https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
		UserVerification: UserVerificationPreferred,
	}
)

type RegistrationResponseJSON struct {
	ID                      string                                    `json:"id"`
	RawID                   string                                    `json:"rawId"`
	Response                AuthenticatorAttestationResponseJSON      `json:"response"`
	AuthenticatorAttachment string                                    `json:"authenticatorAttachment"`
	ClientExtensionResults  AuthenticationExtensionsClientOutputsJSON `json:"clientExtensionResults"`
	Type                    string                                    `json:"type"`
}

type RegistrationCeremonyOption func(*PublicKeyCredentialCreationOptions)

func WithAuthenticatorSelection(authenticatorSelectionCriteria AuthenticatorSelectionCriteria) RegistrationCeremonyOption {
	return func(options *PublicKeyCredentialCreationOptions) {
		options.AuthenticatorSelection = authenticatorSelectionCriteria
	}
}

func WithAttestationPreference(attestation AttestationConveyancePreference) RegistrationCeremonyOption {
	return func(options *PublicKeyCredentialCreationOptions) {
		options.Attestation = attestation
	}
}

func CreateRegistrationCeremonyOptions(rpConfig RPConfig, user WebAuthnUser, opts ...RegistrationCeremonyOption) (*PublicKeyCredentialCreationOptions, *Session, error) {
	userEntity, err := newUserEntity(user.ID, user.Name, user.DisplayName)
	if err != nil {
		return nil, nil, err
	}

	publicKeyCredentialRPEntity := newPublicKeyCredentialRPEntity(rpConfig.ID, rpConfig.Name)

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
		AuthenticatorSelection: defaultAuthenticatorSelection,
		Attestation:            AttestationConveyancePreferenceNone,
	}

	for _, opt := range opts {
		opt(creationOptions)
	}

	session := &Session{
		ID:               user.ID,
		Challenge:        challenge,
		RPID:             rpConfig.ID,
		UserVerification: creationOptions.AuthenticatorSelection.UserVerification,
	}

	return creationOptions, session, nil
}

type RegistrationCelemonyVerifierFunc func(registrationResponse RegistrationResponseJSON) (RegistrationCelemonyVerifier, error)

func VerifyRegistrationCelemonyResponse(
	rpConfig RPConfig, session Session, registrationResponse RegistrationResponseJSON, verifierFunc RegistrationCelemonyVerifierFunc,
) (*CredentialRecord, error) {
	// TODO: Step4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
	// clientExtensionResults := credential.GetClientExtensionResults()

	if verifierFunc == nil {
		verifierFunc = NewRegistrationCelemonyVerifier
	}

	verifier, err := verifierFunc(registrationResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation response verifier: %w", err)
	}

	// Step 7. Verify that the value of C.type is webauthn.create.
	clientDataJSON := verifier.ClientDataJSON()
	if !clientDataJSON.IsRegistrationCelemoney() {
		return nil, fmt.Errorf("invalid ceremony, must be webauthn.create")
	}

	// Step 8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	if valid, err := verifier.VerifyChallenge(session.Challenge); !valid {
		return nil, fmt.Errorf("failed to verify challenge: %w", err)
	}

	// Step 9. Verify that the value of C.origin is an origin expected by the Relying Party.
	if valid, err := verifier.VerifyOrigin(rpConfig.Origins, rpConfig.SubFrameOrigins); !valid {
		return nil, fmt.Errorf("failed to validate origin: %w", err)
	}

	// Step 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	if valid, err := verifier.VerifyRPID(rpConfig.ID); !valid {
		return nil, fmt.Errorf("failed to validate RP ID: %w", err)
	}

	if valid, err := verifier.VerifAuthenticatorDataFlags(session.UserVerification); !valid {
		return nil, fmt.Errorf("failed to validate authenticator data flags: %w", err)
	}

	if valid, err := verifier.VerifyPublicKeyAlgParams(defaultCredentialParameters()); !valid {
		return nil, fmt.Errorf("failed to validate public key algorithm parameters: %w", err)
	}

	if valid, err := verifier.VerifyAttestationStatement(); !valid {
		return nil, fmt.Errorf("failed to validate attestation statement: %w", err)
	}

	// Step 25. Verify that the credentialId is ≤ 1023 bytes.
	// Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
	authenticatorData := verifier.AuthenticatorData()
	if err := authenticatorData.AttestedCredentialData.VerifyCredentialID(); err != nil {
		return nil, fmt.Errorf("failed to verify credential ID: %w", err)
	}

	response := verifier.Response()

	// Step 26. Verify that the credentialId is not yet registered for any user.
	// If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.

	return &CredentialRecord{
		ID:                        authenticatorData.AttestedCredentialData.CredentialID,
		PublicKey:                 authenticatorData.AttestedCredentialData.CredentialPublicKey,
		SignCount:                 authenticatorData.SignCount,
		UvInitialized:             authenticatorData.Flags.HasUserVerified(),
		Transports:                response.transports,
		BackupEligible:            authenticatorData.Flags.HasBackupEligible(),
		BackupState:               authenticatorData.Flags.HasBackupState(),
		AttestationObject:         response.rawAttestationObject,
		AttestationClientDataJSON: response.ClientDataJSON,
	}, nil
}
