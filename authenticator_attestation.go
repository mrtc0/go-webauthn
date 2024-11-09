package webauthn

import (
	"github.com/fxamacker/cbor/v2"
)

// https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorattestationresponsejson
type AuthenticatorAttestationResponseJSON struct {
	ClientDataJSON     string   `json:"clientDataJSON"`
	AuthenticatorData  string   `json:"authenticatorData"`
	Transports         []string `json:"transports"`
	PublicKey          string   `json:"publicKey"`
	PublicKeyAlgorithm int64    `json:"publicKeyAlgorithm"`
	AttestationObject  string   `json:"attestationObject"`
}

type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse

	AttestationObject AttestationObject

	rawAttestationObject []byte

	authenticatorData  AuthenticatorData
	transports         []string
	publicKey          string
	publicKeyAlgorithm int64
}

func (a AuthenticatorAttestationResponseJSON) Parse() (*AuthenticatorAttestationResponse, error) {
	rawAuthData, err := Base64URLEncodedByte(a.AuthenticatorData).Decode()
	if err != nil {
		return nil, err
	}

	authData := AuthenticatorData{}
	if err := authData.Unmarshal(rawAuthData); err != nil {
		return nil, err
	}

	authenticatorResponseJson := AuthenticatorResponseJSON{
		ClientDataJSON: a.ClientDataJSON,
	}
	authenticatorResponse, err := authenticatorResponseJson.Unmarshal()
	if err != nil {
		return nil, err
	}

	rawAttestationObject, err := Base64URLEncodedByte(a.AttestationObject).Decode()
	if err != nil {
		return nil, err
	}

	attestationObject := AttestationObject{}
	if err := cbor.Unmarshal(rawAttestationObject, &attestationObject); err != nil {
		return nil, err
	}

	return &AuthenticatorAttestationResponse{
		AuthenticatorResponse: *authenticatorResponse,
		AttestationObject:     attestationObject,
		rawAttestationObject:  rawAttestationObject,
		authenticatorData:     authData,
		transports:            a.Transports,
		publicKey:             a.PublicKey,
		publicKeyAlgorithm:    a.PublicKeyAlgorithm,
	}, nil
}
