package webauthn

import (
	"bytes"
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

func (a AuthenticatorAssertionResponseJSON) Unmarshal() (*AuthenticatorAssertionResponse, error) {
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

func (a *AuthenticatorAssertionResponse) VerifyAttestaionObject(credential CredentialRecord, hash []byte) (bool, error) {
	if a.AttestationObject == nil {
		return true, nil
	}

	if !a.AuthenticatorData.Flags.HasAttestedCredentialData() {
		return false, fmt.Errorf("attested credential data is not present")
	}

	authenticatorData := &AuthenticatorData{}
	if err := authenticatorData.Unmarshal(a.AttestationObject.AuthData); err != nil {
		return false, fmt.Errorf("failed to unmarshal authenticator data: %w", err)
	}

	credentialID := authenticatorData.AttestedCredentialData.CredentialID
	credentialPublicKey := authenticatorData.AttestedCredentialData.CredentialPublicKey
	if !bytes.Equal(credentialID, credential.ID) || !bytes.Equal(credentialPublicKey, credential.PublicKey) {
		return false, fmt.Errorf("credential mismatch")
	}

	verifier, err := DetermineAttestaionStatement(
		a.AttestationObject.Format,
		a.AttestationObject.AttStatement,
		a.rawAuthData,
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
