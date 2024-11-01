package webauthn

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

type AuthenticationCeremonyOption func(*PublicKeyCredentialRequestOptions)

func (rp *RelyingParty) CreateOptionsForAuthenticationCeremony(user *WebAuthnUser, opts ...AuthenticationCeremonyOption) (*PublicKeyCredentialRequestOptions, *Session, error) {
	if len(user.Credentials) == 0 {
		return nil, nil, fmt.Errorf("no credentials for user")
	}

	var allowedCredentials = make([]PublicKeyCredentialDescriptor, len(user.Credentials))
	for i, credential := range user.Credentials {
		allowedCredentials[i] = PublicKeyCredentialDescriptor{
			Type:       "public-key",
			ID:         credential.ID,
			Transports: []string{}, // TODO
		}
	}

	challenge, err := GenerateChallenge()
	if err != nil {
		return nil, nil, err
	}

	credentialRequestOptions := &PublicKeyCredentialRequestOptions{
		Challenge:         challenge,
		RPID:              rp.RPConfig.ID,
		UserVerification:  "preferred",
		AlloedCredentials: allowedCredentials,
		Timeout:           defaultTimeout,
		Attestation:       "none",
	}

	for _, opt := range opts {
		opt(credentialRequestOptions)
	}

	session := &Session{
		Challenge:          challenge.String(),
		RPID:               rp.RPConfig.Origin,
		UserID:             user.ID,
		UserVerification:   credentialRequestOptions.UserVerification,
		AllowedCredentials: allowedCredentials,
	}

	return credentialRequestOptions, session, nil
}

type DiscoveryUserHandler func(credentialRawID []byte, userHandle []byte) (*WebAuthnUser, *CredentialRecord, error)

func (rp *RelyingParty) Authentication(handler DiscoveryUserHandler, session *Session, credential *AuthenticationResponseJSON) (*WebAuthnUser, *CredentialRecord, error) {
	// Step 3. Let response be credential.response.
	// If response is not an instance of AuthenticatorAssertionResponse,
	// abort the ceremony with a user-visible error.
	authenticatorAssertionResponse, err := credential.Response.ToInstance()
	if err != nil {
		return nil, nil, err
	}

	// TODO: Step 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().

	// Step 5. If options.allowCredentials is not empty,
	// verify that credential.id identifies one of the public key credentials listed in
	// options.allowCredentials.
	if session.AllowedCredentials != nil || len(session.AllowedCredentials) > 0 {
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
	if authenticatorAssertionResponse.UserHandle != nil {
		return nil, nil, fmt.Errorf("user handle is not present")
	}

	user, credentialRecord, err := handler([]byte(credential.RawID), *authenticatorAssertionResponse.UserHandle)
	if err != nil {
		return nil, nil, err
	}

	// Step 7. Let cData, authData and sig denote the value of response’s clientDataJSON,
	// authenticatorData, and signature respectively.
	c, err := ParseClientDataJSON(authenticatorAssertionResponse.ClientDataJSON)
	if err != nil {
		return nil, nil, err
	}

	var authData AuthenticatorData
	rawAuthData, err := authenticatorAssertionResponse.AuthenticatorData.Decode()
	if err != nil {
		return nil, nil, err
	}

	if err := authData.Unmarshal(rawAuthData); err != nil {
		return nil, nil, err
	}

	sig, err := authenticatorAssertionResponse.Signature.Decode()
	if err != nil {
		return nil, nil, err
	}

	// Step 10. Verify that the value of C.type is the string webauthn.get.
	if !c.IsAuthenticationCeremony() {
		return nil, nil, fmt.Errorf("invalid type. must be webauthn.get")
	}

	// Step 11. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
	if !SecureCompare(c.Challenge, session.Challenge) {
		return nil, nil, fmt.Errorf("invalid challenge")
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
	if !bytes.Equal(authData.RPIDHash, rpIDHash[:]) {
		return nil, nil, fmt.Errorf("rpIdHash mismatch")
	}

	// Step 15. Verify that the UP bit of the flags in authData is set.
	if !authData.Flags.HasUserPresent() {
		return nil, nil, fmt.Errorf("user not present")
	}

	// Step 16. Determine whether user verification is required for this assertion.
	// User verification SHOULD be required if, and only if, options.userVerification is set to required.
	if session.UserVerification == "required" && !authData.Flags.HasUserVerified() {
		return nil, nil, fmt.Errorf("user verification required")
	}

	// Step 17. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
	if !authData.Flags.HasBackupEligible() && authData.Flags.HasBackupState() {
		return nil, nil, fmt.Errorf("BE bit is not set, but BS bit is set")
	}

	// Step 18. If the credential backup state is used as part of Relying Party business logic or policy,
	// let currentBe and currentBs be the values of the BE and BS bits, respectively, of the flags in authData.
	// Compare currentBe and currentBs with credentialRecord.backupEligible and credentialRecord.backupState:
	if credentialRecord.BackupEligible && !authData.Flags.HasBackupEligible() {
		return nil, nil, fmt.Errorf("backup eligible but BE bit is not set")
	}

	if !credentialRecord.BackupEligible && authData.Flags.HasBackupEligible() {
		return nil, nil, fmt.Errorf("not backup eligible but BE bit is set")
	}

	// TODO: apply RP policy

	// TODO: Step 19.

	// Step 20. Let hash be the result of computing a hash over the cData using SHA-256.
	cData, err := authenticatorAssertionResponse.ClientDataJSON.Decode()
	if err != nil {
		return nil, nil, err
	}

	sum := sha256.Sum256(cData)
	hash := sum[:]

	// Step 21. Using credentialRecord.publicKey, verify that sig is a valid signature over the
	// binary concatenation of authData and hash.

}
