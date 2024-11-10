package webauthn

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type PublicKeyCredentialJSON struct {
	ID                      string                                    `json:"id"`
	RawID                   string                                    `json:"rawId"`
	AuthenticatorAttachment string                                    `json:"authenticatorAttachment"`
	ClientExtensionResults  AuthenticationExtensionsClientOutputsJSON `json:"clientExtensionResults"`
	Type                    string                                    `json:"type"`
}

type PublicKeyCredential struct {
	ID                      []byte
	RawID                   []byte
	AuthenticatorAttachment string
	ClientExtensionResults  AuthenticationExtensionsClientOutputsJSON
	Type                    string
}

func (a PublicKeyCredentialJSON) Parse() (*PublicKeyCredential, error) {
	decodedRawID, err := Base64URLEncodedByte(a.RawID).Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode credential rawID: %w", err)
	}

	decodedID, err := Base64URLEncodedByte(a.ID).Decode()
	if err != nil {
		return nil, fmt.Errorf("failed to decode credential ID: %w", err)
	}

	return &PublicKeyCredential{
		ID:                      decodedID,
		RawID:                   decodedRawID,
		AuthenticatorAttachment: a.AuthenticatorAttachment,
		ClientExtensionResults:  a.ClientExtensionResults,
		Type:                    a.Type,
	}, nil
}

type AuthenticationResponseJSON struct {
	PublicKeyCredentialJSON

	Response AuthenticatorAssertionResponseJSON `json:"response"`
}

type AuthenticationResponse struct {
	PublicKeyCredential

	Response AuthenticatorAssertionResponse
}

func (a AuthenticationResponseJSON) Parse() (*AuthenticationResponse, error) {
	publicKeyCredential, err := a.PublicKeyCredentialJSON.Parse()
	if err != nil {
		return nil, err
	}

	response, err := a.Response.Parse()
	if err != nil {
		return nil, err
	}

	return &AuthenticationResponse{
		PublicKeyCredential: *publicKeyCredential,
		Response:            *response,
	}, nil
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

func (a AuthenticatorAssertionResponseJSON) Parse() (*AuthenticatorAssertionResponse, error) {
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
