package webauthn

import (
	"fmt"
)

type AuthenticationCeremonyOption func(*PublicKeyCredentialRequestOptions)

func WithUserVerification(userVerification UserVerification) AuthenticationCeremonyOption {
	return func(opts *PublicKeyCredentialRequestOptions) {
		opts.UserVerification = userVerification
	}
}

func WithAttestaion(attestation AttestationConveyancePreference) AuthenticationCeremonyOption {
	return func(opts *PublicKeyCredentialRequestOptions) {
		opts.Attestation = attestation
	}
}

func CreateAuthenticationOptions(rpConfig RPConfig, sessionID []byte, opts ...AuthenticationCeremonyOption) (*PublicKeyCredentialRequestOptions, *Session, error) {
	challenge, err := GenerateChallenge()
	if err != nil {
		return nil, nil, err
	}

	credentialRequestOptions := &PublicKeyCredentialRequestOptions{
		Challenge:        challenge,
		RPID:             rpConfig.ID,
		UserVerification: UserVerificationPreferred,
		Timeout:          defaultTimeout,
		Attestation:      AttestationConveyancePreferenceNone,
	}

	for _, opt := range opts {
		opt(credentialRequestOptions)
	}

	if valid, err := credentialRequestOptions.IsValid(); !valid {
		return nil, nil, fmt.Errorf("invalid options: %w", err)
	}

	// TODO: Set AllowedCredentials
	session, err := NewWebAuthnSession(
		sessionID, challenge, rpConfig.ID, credentialRequestOptions.UserVerification, nil,
	)
	if err != nil {
		return nil, nil, err
	}

	return credentialRequestOptions, session, nil
}

type AuthenticationCelemonyVerifierFunc func(
	responseJSON AuthenticationResponseJSON,
	allowedCredentials []PublicKeyCredentialDescriptor,
	discoveryUserHandler DiscoveryUserHandler,
	opts ...AuthenticatorAssertionResponseVerifierOption,
) (AuthenticationCelemonyVerifier, error)

type VerifyDiscoverableCredentialAuthenticationParam struct {
	RPConfig           RPConfig
	Challenge          []byte
	AllowedCredentials []PublicKeyCredentialDescriptor
	UserVerification   UserVerification
}

func VerifyDiscoverableCredentialAuthenticationResponse(
	param VerifyDiscoverableCredentialAuthenticationParam,
	handler DiscoveryUserHandler,
	response AuthenticationResponseJSON,
	verifierFunc AuthenticationCelemonyVerifierFunc,
	opts ...AuthenticatorAssertionResponseVerifierOption,
) (*WebAuthnUser, *CredentialRecord, error) {
	if verifierFunc == nil {
		verifierFunc = NewAuthenticationCelemonyVerifier
	}

	verifier, err := verifierFunc(response, param.AllowedCredentials, handler, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create attestation response verifier: %w", err)
	}

	// Step 10. Verify that the value of C.type is the string webauthn.get.
	if !verifier.IsAuthenticationCeremony() {
		return nil, nil, fmt.Errorf("invalid type. must be webauthn.get")
	}

	// Step 11. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	if result, err := verifier.VerifyChallenge(param.Challenge); !result {
		return nil, nil, fmt.Errorf("failed to verify challenge: %w", err)
	}

	// Step 12. Verify that the value of C.origin is an origin expected by the Relying Party.
	// See § 13.4.9 Validating the origin of a credential for guidance.
	if valid, err := verifier.VerifyOrigin(param.RPConfig.Origins, param.RPConfig.SubFrameOrigins); !valid {
		return nil, nil, fmt.Errorf("failed to validate origin: %w", err)
	}

	// Step 14. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	if !verifier.VerifyRPID(param.RPConfig.ID) {
		return nil, nil, fmt.Errorf("RP ID mismatch")
	}

	// Step 15. Verify that the UP bit of the flags in authData is set.
	if !verifier.VerifyUserPresent() {
		return nil, nil, fmt.Errorf("user not present")
	}

	// Step 16. Determine whether user verification is required for this assertion.
	// User verification SHOULD be required if, and only if, options.userVerification is set to required.
	if !verifier.VerifyUserVerified(param.UserVerification) {
		return nil, nil, fmt.Errorf("user verification failed")
	}

	if result, err := verifier.VerifyFlags(); !result {
		return nil, nil, fmt.Errorf("failed to verify flags: %w", err)
	}

	// TODO: apply RP policy

	// TODO: Step 19. Verify that the values of the client extension outputs

	if result, err := verifier.VerifySignature(); !result {
		return nil, nil, fmt.Errorf("failed to verify signature: %w", err)
	}

	// Step 22. If authData.signCount is nonzero or credentialRecord.signCount is nonzero,
	// then run the following sub-step:
	if result, err := verifier.VerifySignCount(); !result {
		fmt.Printf("failed to evaluate sign count: %s\n", err)
		// return nil, nil, fmt.Errorf("failed to evaluate sign count: %w", err)
	}

	// Step 23. If response.attestationObject is present and the Relying Party wishes to verify the attestation
	// then perform CBOR decoding on attestationObject to obtain the attestation statement format fmt,
	// and the attestation statement attStmt.
	if result, err := verifier.VerifyAttestaionObject(); !result {
		return nil, nil, fmt.Errorf("failed to verify attestation object: %w", err)
	}

	// Step 24. Update credentialRecord with new state values:
	user := verifier.GetUser()
	credential := verifier.GetUserCredential()
	authenticatorAssertionResponse := verifier.GetAuthenticatorAssertionResponse()
	credential.UpdateState(&authenticatorAssertionResponse)

	return &user, &credential, nil
}
