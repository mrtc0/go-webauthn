package webauthn

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

type AuthenticationCeremonyOption func(*PublicKeyCredentialRequestOptions)

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
		Attestation:      "none",
	}

	for _, opt := range opts {
		opt(credentialRequestOptions)
	}

	session := &Session{
		ID:               sessionID,
		Challenge:        challenge,
		RPID:             rp.RPConfig.Origin,
		UserVerification: credentialRequestOptions.UserVerification,
	}

	return credentialRequestOptions, session, nil
}

type DiscoveryUserHandler func(credentialRawID []byte, userHandle string) (*WebAuthnUser, *CredentialRecord, error)

func (rp *RelyingParty) Authentication(handler DiscoveryUserHandler, session *Session, credential *AuthenticationResponseJSON) (*WebAuthnUser, *CredentialRecord, error) {
	// Step 3. Let response be credential.response.
	// If response is not an instance of AuthenticatorAssertionResponse,
	// abort the ceremony with a user-visible error.
	authenticatorAssertionResponse, err := credential.Response.Unmarshal()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// TODO: Step 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().

	// Step 5. If options.allowCredentials is not empty,
	// verify that credential.id identifies one of the public key credentials listed in
	// options.allowCredentials.
	if len(session.AllowedCredentials) > 0 {
		found := false
		for _, allowedCredential := range session.AllowedCredentials {
			fmt.Println(allowedCredential.ID, []byte(credential.ID))
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

	user, credentialRecord, err := handler([]byte(credential.RawID), authenticatorAssertionResponse.UserHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Step 7. Let cData, authData and sig denote the value of response’s clientDataJSON,
	// authenticatorData, and signature respectively.
	c := authenticatorAssertionResponse.GetParsedClientDataJSON()

	rawAuthData := authenticatorAssertionResponse.rawAuthData

	sig := authenticatorAssertionResponse.Signature

	// Step 10. Verify that the value of C.type is the string webauthn.get.
	if !c.IsAuthenticationCeremony() {
		return nil, nil, fmt.Errorf("invalid type. must be webauthn.get")
	}

	// Step 11. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	challenge, err := Base64URLEncodedByte(c.Challenge).Decode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode challenge: %w", err)
	}

	if !SecureCompareByte(challenge, session.Challenge) {
		return nil, nil, fmt.Errorf("challenge mismatch")
	}

	// Step 12. Verify that the value of C.origin is an origin expected by the Relying Party.
	// See § 13.4.9 Validating the origin of a credential for guidance.
	if c.Origin != rp.RPConfig.Origin {
		return nil, nil, fmt.Errorf("invalid origin")
	}

	if c.TopOrigin != "" {
		if !c.CrossOrigin {
			return nil, nil, fmt.Errorf("topOrigin present but crossOrigin is false")
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
				return nil, nil, fmt.Errorf("top origin mismatch")
			}
		}
	}

	// Step 14. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
	rpIDHash := sha256.Sum256([]byte(rp.RPConfig.ID))
	if !bytes.Equal(authenticatorAssertionResponse.AuthenticatorData.RPIDHash, rpIDHash[:]) {
		return nil, nil, fmt.Errorf("rpIdHash mismatch")
	}

	// Step 15. Verify that the UP bit of the flags in authData is set.
	if !authenticatorAssertionResponse.AuthenticatorData.Flags.HasUserPresent() {
		return nil, nil, fmt.Errorf("user not present")
	}

	// Step 16. Determine whether user verification is required for this assertion.
	// User verification SHOULD be required if, and only if, options.userVerification is set to required.
	if session.UserVerification.IsRequired() && !authenticatorAssertionResponse.AuthenticatorData.Flags.HasUserVerified() {
		return nil, nil, fmt.Errorf("user verification required")
	}

	// Step 17. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
	if !authenticatorAssertionResponse.AuthenticatorData.Flags.HasBackupEligible() && authenticatorAssertionResponse.AuthenticatorData.Flags.HasBackupState() {
		return nil, nil, fmt.Errorf("BE bit is not set, but BS bit is set")
	}

	// Step 18. If the credential backup state is used as part of Relying Party business logic or policy,
	// let currentBe and currentBs be the values of the BE and BS bits, respectively, of the flags in authData.
	// Compare currentBe and currentBs with credentialRecord.backupEligible and credentialRecord.backupState:
	if credentialRecord.BackupEligible && !authenticatorAssertionResponse.AuthenticatorData.Flags.HasBackupEligible() {
		return nil, nil, fmt.Errorf("backup eligible but BE bit is not set")
	}

	if !credentialRecord.BackupEligible && authenticatorAssertionResponse.AuthenticatorData.Flags.HasBackupEligible() {
		return nil, nil, fmt.Errorf("not backup eligible but BE bit is set")
	}

	// TODO: apply RP policy

	// TODO: Step 19.

	// Step 20. Let hash be the result of computing a hash over the cData using SHA-256.
	cData := authenticatorAssertionResponse.ClientDataJSON
	sum := sha256.Sum256([]byte(cData))
	hash := sum[:]

	// Step 21. Using credentialRecord.publicKey, verify that sig is a valid signature over the
	// binary concatenation of authData and hash.
	publicKey, err := credentialRecord.GetPublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key: %w", err)
	}

	sigData := append(rawAuthData, hash...)
	valid, err := publicKey.Verify(sigData, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify signature: %w", err)
	}

	if !valid {
		return nil, nil, fmt.Errorf("invalid signature")
	}

	// Step 22. If authData.signCount is nonzero or credentialRecord.signCount is nonzero,
	// then run the following sub-step:
	validSignCount := false
	if authenticatorAssertionResponse.AuthenticatorData.SignCount > credentialRecord.SignCount {
		validSignCount = true
	} else {
		// TODO: apply RP policy
		validSignCount = false
		fmt.Println("singCount: ", validSignCount)
	}

	// Step 23. If response.attestationObject is present and the Relying Party wishes to verify the attestation
	// then perform CBOR decoding on attestationObject to obtain the attestation statement format fmt,
	// and the attestation statement attStmt.

	if authenticatorAssertionResponse.AttestationObject != nil {
		if !authenticatorAssertionResponse.AuthenticatorData.Flags.HasAttestedCredentialData() {
			return nil, nil, fmt.Errorf("attested credential data is not present")
		}

		authenticatorData := &AuthenticatorData{}
		if err := authenticatorData.Unmarshal(authenticatorAssertionResponse.AttestationObject.AuthData); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal authenticator data: %w", err)
		}

		credentialID := authenticatorData.AttestedCredentialData.CredentialID
		credentialPublicKey := authenticatorData.AttestedCredentialData.CredentialPublicKey
		if bytes.Equal(credentialID, credentialRecord.ID) || bytes.Equal(credentialPublicKey, credentialRecord.PublicKey) {
			return nil, nil, fmt.Errorf("credential mismatch")
		}

		verifier, err := DetermineAttestaionStatement(
			authenticatorAssertionResponse.AttestationObject.Format,
			authenticatorAssertionResponse.AttestationObject.AttStatement,
			authenticatorAssertionResponse.rawAuthData,
			hash)
		if err != nil {
			return nil, nil, err
		}

		_, _, err = verifier.Verify()
		if err != nil {
			return nil, nil, err
		}
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
