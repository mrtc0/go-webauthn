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

func (rp *RelyingParty) CreateOptionsForAuthenticationCeremony(sessionID []byte, opts ...AuthenticationCeremonyOption) (*PublicKeyCredentialRequestOptions, *Session, error) {
	challenge, err := GenerateChallenge()
	if err != nil {
		return nil, nil, err
	}

	credentialRequestOptions := &PublicKeyCredentialRequestOptions{
		Challenge:        challenge,
		RPID:             rp.RPConfig.ID,
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
		sessionID, challenge, rp.RPConfig.ID, credentialRequestOptions.UserVerification, nil,
	)
	if err != nil {
		return nil, nil, err
	}

	return credentialRequestOptions, session, nil
}

type DiscoveryUserHandler func(credentialRawID []byte, userHandle string) (*WebAuthnUser, *CredentialRecord, error)

// AuthenticationWithDiscoverableCredential is the ceremony for authenticating a user with a discoverable credential.
func (rp *RelyingParty) AuthenticationWithDiscoverableCredential(handler DiscoveryUserHandler, session *Session, credential *AuthenticationResponseJSON) (*WebAuthnUser, *CredentialRecord, error) {
	// Step 3. Let response be credential.response.
	// If response is not an instance of AuthenticatorAssertionResponse,
	// abort the ceremony with a user-visible error.
	authenticatorAssertionResponse, err := credential.Response.Parse()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// TODO: Step 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().

	// Step 5. If options.allowCredentials is not empty,
	// verify that credential.id identifies one of the public key credentials listed in
	// options.allowCredentials.
	if len(session.AllowedCredentials) > 0 {
		found := false
		for _, allowedCredential := range session.AllowedCredentials {
			if SecureCompareByte(allowedCredential.ID, []byte(credential.ID)) {
				found = true
				break
			}
		}

		if !found {
			return nil, nil, fmt.Errorf("allowed credentials not found in session")
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
	if authenticatorAssertionResponse.UserHandle == "" {
		return nil, nil, fmt.Errorf("user handle is not present")
	}

	decodedCredentialID, err := Base64URLEncodedByte(credential.RawID).Decode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode credential rawID: %w", err)
	}

	user, credentialRecord, err := handler(decodedCredentialID, authenticatorAssertionResponse.UserHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user: %w", err)
	}

	verifier := NewAuthenticatorAssertionResponseVerifier(authenticatorAssertionResponse, credentialRecord)

	// Step 10. Verify that the value of C.type is the string webauthn.get.
	if !verifier.IsAuthenticationCeremony() {
		return nil, nil, fmt.Errorf("invalid type. must be webauthn.get")
	}

	// Step 11. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	if result, err := verifier.VerifyChallenge(session.Challenge); !result {
		return nil, nil, fmt.Errorf("failed to verify challenge: %w", err)
	}

	// Step 12. Verify that the value of C.origin is an origin expected by the Relying Party.
	// See § 13.4.9 Validating the origin of a credential for guidance.
	if valid, err := verifier.VerifyOrigin(rp.RPConfig.Origins, rp.RPConfig.SubFrameOrigins); !valid {
		return nil, nil, fmt.Errorf("failed to validate origin: %w", err)
	}

	// Step 14. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	if !verifier.VerifyRPID(rp.RPConfig.ID) {
		return nil, nil, fmt.Errorf("RP ID mismatch")
	}

	// Step 15. Verify that the UP bit of the flags in authData is set.
	if !verifier.VerifyUserPresent() {
		return nil, nil, fmt.Errorf("user not present")
	}

	// Step 16. Determine whether user verification is required for this assertion.
	// User verification SHOULD be required if, and only if, options.userVerification is set to required.
	if !verifier.VerifyUserVerified(session.UserVerification) {
		return nil, nil, fmt.Errorf("user verification failed")
	}

	if result, err := verifier.VerifyFlags(); !result {
		return nil, nil, fmt.Errorf("failed to verify flags: %w", err)
	}

	// TODO: apply RP policy

	// TODO: Step 19.

	if result, err := verifier.VerifySignature(); !result {
		return nil, nil, fmt.Errorf("failed to verify signature: %w", err)
	}

	// Step 22. If authData.signCount is nonzero or credentialRecord.signCount is nonzero,
	// then run the following sub-step:
	if result, err := verifier.EvaluateSignCount(); !result {
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
	credentialRecord.SignCount = authenticatorAssertionResponse.AuthenticatorData.SignCount
	credentialRecord.BackupState = authenticatorAssertionResponse.AuthenticatorData.Flags.HasBackupState()

	if !credentialRecord.UvInitialized {
		credentialRecord.UvInitialized = authenticatorAssertionResponse.AuthenticatorData.Flags.HasUserVerified()
	}

	credentialRecord.AttestationObject = authenticatorAssertionResponse.rawAttestationObject
	credentialRecord.AttestationClientDataJSON = authenticatorAssertionResponse.ClientDataJSON

	return user, credentialRecord, nil
}
