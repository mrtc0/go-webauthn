package webauthn

import (
	"encoding/binary"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// https://www.w3.org/TR/webauthn-3/#authdata-flags
type AuthenticatorFlags byte

const (
	// https://www.w3.org/TR/webauthn-3/#authdata-flags
	FlagUserPresent AuthenticatorFlags = 1 << iota
	FlagRFU1
	FlagUserVerified
	FlagBackupEligible
	FlagBackupState
	FlagRFU2
	FlagAttestedCredentialData
	FlagHasExtensions
)

func (a AuthenticatorFlags) HasAttestedCredentialData() bool {
	return (a & FlagAttestedCredentialData) == FlagAttestedCredentialData
}

func (a AuthenticatorFlags) HasExtensions() bool {
	return (a & FlagHasExtensions) == FlagHasExtensions
}

func (a AuthenticatorFlags) HasUserPresent() bool {
	return (a & FlagUserPresent) == FlagUserPresent
}

func (a AuthenticatorFlags) HasUserVerified() bool {
	return (a & FlagUserVerified) == FlagUserVerified
}

func (a AuthenticatorFlags) HasBackupEligible() bool {
	return (a & FlagBackupEligible) == FlagBackupEligible
}

func (a AuthenticatorFlags) HasBackupState() bool {
	return (a & FlagBackupState) == FlagBackupState
}

// https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorattestationresponsejson
type AuthenticatorAttestationResponseJSON struct {
	ClientDataJSON     string   `json:"clientDataJSON"`
	AuthenticatorData  string   `json:"authenticatorData"`
	Transports         []string `json:"transports"`
	PublicKey          string   `json:"publicKey"`
	PublicKeyAlgorithm int64    `json:"publicKeyAlgorithm"`
	AttestationObject  string   `json:"attestationObject"`
}

type AuthenticatorResponse struct {
	ClientDataJSON Base64URLEncodedByte `json:"clientDataJSON"`
}

type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse

	AttestationObject Base64URLEncodedByte `json:"attestationObject"`

	authenticatorData  string
	transports         []string
	publicKey          string
	publicKeyAlgorithm int64
}

func (a *AuthenticatorAttestationResponse) GetTransports() []string {
	return a.transports
}

func (a *AuthenticatorAttestationResponse) GetPublicKey() string {
	return a.publicKey
}

func (a *AuthenticatorAttestationResponse) GetPublicKeyAlgorithm() int64 {
	return a.publicKeyAlgorithm
}

func (a *AuthenticatorAttestationResponse) GetAuthenticatorData() string {
	return a.authenticatorData
}

func (a AuthenticatorAttestationResponseJSON) ToInstance() (*AuthenticatorAttestationResponse, error) {
	return &AuthenticatorAttestationResponse{
		AuthenticatorResponse: AuthenticatorResponse{
			ClientDataJSON: Base64URLEncodedByte(a.ClientDataJSON),
		},
		AttestationObject:  Base64URLEncodedByte(a.AttestationObject),
		authenticatorData:  a.AuthenticatorData,
		transports:         a.Transports,
		publicKey:          a.PublicKey,
		publicKeyAlgorithm: a.PublicKeyAlgorithm,
	}, nil
}

// https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
type AuthenticatorData struct {
	RPIDHash               []byte                 `json:"rpid"`
	Flags                  AuthenticatorFlags     `json:"flags"`
	SignCount              uint32                 `json:"sign_count"`
	AttestedCredentialData AttestedCredentialData `json:"att_data"`
	Extensions             []byte                 `json:"ext_data"`
}

const (
	AuthenticatorDataMinSize = 37
)

func (a *AuthenticatorData) Unmarshal(data []byte) error {
	if len(data) < AuthenticatorDataMinSize {
		return errors.New("authenticator data is too short, expected at least 37 bytes")
	}

	/*
		+--------+------+-------+----------------------+-----------+
		| RP ID  |      |       |                      |           |
		| HASH   |FLAGS |COUNTER| ATTESTED CRED DATA   | EXTENSIONS|
		|        |      |       |                      |           |
		+--------+------+-------+----------------------+-----------+
		|  32    |  1   |   4   |    variable length   |  variable |
		| bytes  | byte | bytes |                      |   length  |
		+--------+------+-------+----------------------+-----------+
	*/

	a.RPIDHash = data[:32]
	a.Flags = AuthenticatorFlags(data[32])
	a.SignCount = binary.BigEndian.Uint32(data[33:37])

	var extensionData []byte
	if a.Flags.HasAttestedCredentialData() {
		// TODO: check if the data is long enough
		a.AttestedCredentialData.AAGUID = data[37:53]              // aaguid is 16 bytes
		credentialIDLength := binary.BigEndian.Uint16(data[53:55]) // credential id length is 2 bytes
		if credentialIDLength > 1023 {
			return errors.New("credential id length is too long")
		}

		a.AttestedCredentialData.CredentialIDLength = credentialIDLength
		a.AttestedCredentialData.CredentialID = data[55 : 55+a.AttestedCredentialData.CredentialIDLength]

		var v interface{}
		rest, err := cbor.UnmarshalFirst(data[55+a.AttestedCredentialData.CredentialIDLength:], &v)
		if err != nil {
			return err
		}

		b, err := cbor.Marshal(v)
		if err != nil {
			return err
		}

		a.AttestedCredentialData.CredentialPublicKey = b
		extensionData = rest
	}

	if a.Flags.HasExtensions() {
		a.Extensions = extensionData
	}

	return nil
}
