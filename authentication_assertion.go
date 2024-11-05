package webauthn

import "github.com/fxamacker/cbor/v2"

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
