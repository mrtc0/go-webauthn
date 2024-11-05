package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// https://www.w3.org/TR/webauthn-3/#enum-credentialType
const PublicKeyCredentialTypePublicKey = "public-key"

type PublicKeyCredentialEntity struct {
	Name string `json:"name"`
}

type PublicKeyCredentialRpEntity struct {
	PublicKeyCredentialEntity

	ID string `json:"id"`
}

type PublicKeyCredentialUserEntity struct {
	ID          []byte `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PublicKeyCredentialParameters struct {
	Type string                  `json:"type"`
	Alg  COSEAlgorithmIdentifier `json:"alg"`
}

type PublicKeyCredentialDescriptor struct {
	Type       string   `json:"type"`
	ID         []byte   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment string           `json:"authenticatorAttachment,omitempty"`
	ResidentKey             string           `json:"residentKey,omitempty"`
	RequireResidentKey      bool             `json:"requireResidentKey,omitempty"`
	UserVerification        UserVerification `json:"userVerification,omitempty"`
}

type PublicKeyCredentialCreationOptions struct {
	RP   PublicKeyCredentialRpEntity   `json:"rp"`
	User PublicKeyCredentialUserEntity `json:"user"`

	Challenge        Base64URLEncodedByte            `json:"challenge"`
	PubKeyCredParams []PublicKeyCredentialParameters `json:"pubKeyCredParams,omitempty"`

	Timeout                int64                                `json:"timeout,omitempty"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor      `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection AuthenticatorSelectionCriteria       `json:"authenticatorSelection,omitempty"`
	Hints                  []string                             `json:"hints,omitempty"`
	Attestation            string                               `json:"attestation,omitempty"`
	AttestationFormats     []string                             `json:"attestationFormats,omitempty"`
	Extensions             AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

type RegistrationResponseJSON struct {
	ID                      string                                    `json:"id"`
	RawID                   string                                    `json:"rawId"`
	Response                AuthenticatorAttestationResponseJSON      `json:"response"`
	AuthenticatorAttachment string                                    `json:"authenticatorAttachment"`
	ClientExtensionResults  AuthenticationExtensionsClientOutputsJSON `json:"clientExtensionResults"`
	Type                    string                                    `json:"type"`
}

// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions
type PublicKeyCredentialRequestOptions struct {
	Challenge Base64URLEncodedByte `json:"challenge"`
	Timeout   int64                `json:"timeout,omitempty"`

	RPID               string                               `json:"rpId"`
	AlloedCredentials  []PublicKeyCredentialDescriptor      `json:"allowCredentials,omitempty"`
	UserVerification   UserVerification                     `json:"userVerification,omitempty"`
	Hints              []string                             `json:"hints,omitempty"`
	Attestation        string                               `json:"attestation,omitempty" default:"none"`
	AttestationFormats []string                             `json:"attestationFormats,omitempty"`
	Extensions         AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

type PublicKeyCredential struct {
	ID                      string                                    `json:"id"`
	RawID                   string                                    `json:"rawId"`
	AuthenticatorAttachment string                                    `json:"authenticatorAttachment"`
	ClientExtensionResults  AuthenticationExtensionsClientOutputsJSON `json:"clientExtensionResults"`
	Type                    string                                    `json:"type"`
}

// https://www.w3.org/TR/webauthn-3/#credential-record
type CredentialRecord struct {
	// Recommended
	Type           string
	ID             []byte
	PublicKey      []byte
	SignCount      uint32
	Transports     []string
	UvInitialized  bool
	BackupEligible bool
	BackupState    bool
	// Optional
	AttestationObject         []byte
	AttestationClientDataJSON []byte
}

type PublicKeyData interface {
	Verify(data []byte, signature []byte) (bool, error)
}

// publicKeyData represents a COSE_Key object
// https://datatracker.ietf.org/doc/html/rfc8152#section-13
type publicKeyData struct {
	// https://datatracker.ietf.org/doc/html/rfc8152#section-13
	KeyType   int64 `cbor:"1,keyasint" json:"kty"` // required
	Algorithm int64 `cbor:"3,keyasint" json:"alg"` // required
}

type OKPPublicKeyData struct {
	publicKeyData publicKeyData
}

// EC2PublicKeyData represents an Elliptic Curve public key
// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
// https://datatracker.ietf.org/doc/html/rfc8392#appendix-A.2.3
type EC2PublicKeyData struct {
	publicKeyData

	Curve       int64  `cbor:"-1,keyasint" json:"crv"`
	XCoordinate []byte `cbor:"-2,keyasint" json:"x"`
	YCoordinate []byte `cbor:"-3,keyasint" json:"y"`
}

func (p *OKPPublicKeyData) Verify(data []byte, signature []byte) (bool, error) {
	return false, nil
}

func (p *EC2PublicKeyData) Verify(data []byte, signature []byte) (bool, error) {
	var curve elliptic.Curve
	var hasher crypto.Hash

	// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
	switch p.Algorithm {
	case int64(AlgES256):
		curve = elliptic.P256()
		hasher = crypto.SHA256
	case int64(AlgES384):
		curve = elliptic.P384()
		hasher = crypto.SHA384
	case int64(AlgES512):
		curve = elliptic.P521()
		hasher = crypto.SHA512
	default:
		return false, fmt.Errorf("unsupported algorithm: %d", p.Algorithm)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(p.XCoordinate),
		Y:     new(big.Int).SetBytes(p.YCoordinate),
	}

	h := hasher.New()
	if _, err := h.Write(data); err != nil {
		return false, err
	}

	return ecdsa.VerifyASN1(pubKey, h.Sum(nil), signature), nil
}

type COSEKeyType int

// https://www.iana.org/assignments/cose/cose.xhtml#key-type
const (
	COSEKeyTypeReserved COSEKeyType = iota
	COSEKeyTypeOKP
	COSEKeyTypeEC2
	COSEKeyTypeRSA
	COSEKeyTypeSymmetric
	COSEKeyTypeHSS_LMS
	COSEKeyTypeWalnutDSA
)

// The credential public key encoded in COSE_Key format, using the CTAP2 canonical CBOR encoding form.
func (r *CredentialRecord) GetPublicKey() (PublicKeyData, error) {
	pk := &publicKeyData{}

	// ref. https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form
	mode, err := cbor.DecOptions{
		// If map keys are present that an implementation does not understand, they MUST be ignored.
		DupMapKey: cbor.DupMapKeyEnforcedAPF, // don't allow duplicate map keys
		// Indefinite-length items must be made into definite-length items.
		IndefLength: cbor.IndefLengthForbidden,
		// Because some authenticators are memory constrained, the depth of nested CBOR structures
		// used by all message encodings is limited to at most four (4) levels of any combination of
		// CBOR maps and/or CBOR arrays.
		MaxNestedLevels: 4,
		// Tags as defined in Section 2.4 in [RFC7049] MUST NOT be present.
		TagsMd: cbor.TagsForbidden,
	}.DecMode()
	if err != nil {
		return nil, err
	}

	_, err = mode.UnmarshalFirst(r.PublicKey, &pk)
	if err != nil {
		return nil, err
	}

	switch COSEKeyType(pk.KeyType) {
	case COSEKeyTypeOKP:
		return nil, fmt.Errorf("unsupported key type: %d", pk.KeyType)
	case COSEKeyTypeEC2:
		ec2PublicKey := &EC2PublicKeyData{}
		_, err := mode.UnmarshalFirst(r.PublicKey, ec2PublicKey)
		if err != nil {
			return nil, err
		}

		return ec2PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %d", pk.KeyType)
	}
}
