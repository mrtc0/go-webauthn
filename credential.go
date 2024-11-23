package webauthn

import (
	"fmt"

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
	Attestation            AttestationConveyancePreference      `json:"attestation,omitempty"`
	AttestationFormats     []string                             `json:"attestationFormats,omitempty"`
	Extensions             AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions
type PublicKeyCredentialRequestOptions struct {
	Challenge Base64URLEncodedByte `json:"challenge"`
	Timeout   int64                `json:"timeout,omitempty"`

	RPID               string                               `json:"rpId"`
	AlloedCredentials  []PublicKeyCredentialDescriptor      `json:"allowCredentials,omitempty"`
	UserVerification   UserVerification                     `json:"userVerification,omitempty"`
	Hints              []string                             `json:"hints,omitempty"`
	Attestation        AttestationConveyancePreference      `json:"attestation,omitempty" default:"none"`
	AttestationFormats []string                             `json:"attestationFormats,omitempty"`
	Extensions         AuthenticationExtensionsClientInputs `json:"extensions,omitempty"`
}

func (o PublicKeyCredentialRequestOptions) IsValid() (bool, error) {
	if !o.UserVerification.IsValid() {
		return false, fmt.Errorf("invalid user verification")
	}

	if !o.Attestation.IsValid() {
		return false, fmt.Errorf("invalid attestation")
	}

	return true, nil
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

func (c *CredentialRecord) UpdateState(authenticatorAssertionResponse *AuthenticatorAssertionResponse) {
	c.SignCount = authenticatorAssertionResponse.AuthenticatorData.SignCount
	c.BackupState = authenticatorAssertionResponse.AuthenticatorData.Flags.HasBackupState()

	if !c.UvInitialized {
		c.UvInitialized = authenticatorAssertionResponse.AuthenticatorData.Flags.HasUserVerified()
	}

	c.AttestationObject = authenticatorAssertionResponse.rawAttestationObject
	c.AttestationClientDataJSON = authenticatorAssertionResponse.ClientDataJSON
}

// The credential public key encoded in COSE_Key format, using the CTAP2 canonical CBOR encoding form.
func (r *CredentialRecord) GetPublicKey() (PublicKeyData, error) {
	return ParsePublicKey(r.PublicKey)
}

func ParsePublicKey(publicKey []byte) (PublicKeyData, error) {
	pk := &PublicKeyDataBase{}

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

	_, err = mode.UnmarshalFirst(publicKey, &pk)
	if err != nil {
		return nil, err
	}

	switch COSEKeyType(pk.KeyType) {
	case COSEKeyTypeOKP:
		octetPublicKey := &OKPPublicKeyData{}
		_, err := mode.UnmarshalFirst(publicKey, octetPublicKey)
		if err != nil {
			return nil, err
		}

		return octetPublicKey, nil
	case COSEKeyTypeEC2:
		ec2PublicKey := &EC2PublicKeyData{}
		_, err := mode.UnmarshalFirst(publicKey, ec2PublicKey)
		if err != nil {
			return nil, err
		}

		return ec2PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %d", pk.KeyType)
	}
}

func newUserEntity(id []byte, name, displayName string) (*PublicKeyCredentialUserEntity, error) {
	if len(id) > 64 || len(id) == 0 {
		return nil, fmt.Errorf("ID must be between 1 and 64 bytes")
	}

	return &PublicKeyCredentialUserEntity{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
	}, nil
}

func newPublicKeyCredentialRPEntity(id, name string) *PublicKeyCredentialRpEntity {
	return &PublicKeyCredentialRpEntity{
		ID: id,
		PublicKeyCredentialEntity: PublicKeyCredentialEntity{
			Name: name,
		},
	}
}
