package webauthn

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type AttestationConveyancePreference string

const (
	AttestationConveyancePreferenceNone       AttestationConveyancePreference = "none"
	AttestationConveyancePreferenceDirect     AttestationConveyancePreference = "direct"
	AttestationConveyancePreferenceIndirect   AttestationConveyancePreference = "indirect"
	AttestationConveyancePreferenceEnterprise AttestationConveyancePreference = "enterprise"
)

func (a AttestationConveyancePreference) String() string {
	return string(a)
}

func (a AttestationConveyancePreference) IsValid() bool {
	switch a {
	case AttestationConveyancePreferenceNone, AttestationConveyancePreferenceDirect, AttestationConveyancePreferenceIndirect, AttestationConveyancePreferenceEnterprise:
		return true
	default:
		return false
	}
}

// https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data
type AttestedCredentialData struct {
	AAGUID              []byte `json:"aaguid"`
	CredentialIDLength  uint16 `json:"credential_id_length"`
	CredentialID        []byte `json:"credential_id"`
	CredentialPublicKey []byte `json:"public_key"`
}

type AttestationObject struct {
	AuthData     []byte         `cbor:"authData"`
	Format       string         `cbor:"fmt"`
	AttStatement map[string]any `cbor:"attStmt"`
}

type coseKey struct {
	Kty       int             `cbor:"1,keyasint,omitempty"`
	Kid       []byte          `cbor:"2,keyasint,omitempty"`
	Alg       int             `cbor:"3,keyasint,omitempty"`
	KeyOpts   int             `cbor:"4,keyasint,omitempty"`
	IV        []byte          `cbor:"5,keyasint,omitempty"`
	CrvOrNOrK cbor.RawMessage `cbor:"-1,keyasint,omitempty"`
	XOrE      cbor.RawMessage `cbor:"-2,keyasint,omitempty"`
	Y         cbor.RawMessage `cbor:"-3,keyasint,omitempty"`
	D         []byte          `cbor:"-4,keyasint,omitempty"`
}

func (a *AttestedCredentialData) DecodeCredentialPublicKey() (*coseKey, error) {
	var key coseKey
	err := cbor.Unmarshal(a.CredentialPublicKey, &key)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (a *AttestedCredentialData) VerifyPublicKeyAlgParams(publicKeyCredParams []PublicKeyCredentialParameters) error {
	key, err := a.DecodeCredentialPublicKey()
	if err != nil {
		return err
	}

	for _, param := range publicKeyCredParams {
		if param.Alg == COSEAlgorithmIdentifier(key.Alg) {
			return nil
		}
	}

	return fmt.Errorf("public key algorithm %d is not allowed", key.Alg)
}

func (a *AttestedCredentialData) VerifyCredentialID() error {
	if len(a.CredentialID) > 1023 {
		return fmt.Errorf("credential id length is too long, expected at most 1023 bytes, got %d", len(a.CredentialID))
	}

	return nil
}
