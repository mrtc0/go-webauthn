package webauthn

import "github.com/fxamacker/cbor/v2"

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
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ResidentKey             string `json:"residentKey,omitempty"`
	RequireResidentKey      bool   `json:"requireResidentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
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
	UserVerification   string                               `json:"userVerification,omitempty"`
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

type AuthenticationResponseJSON struct {
	PublicKeyCredential

	Response AuthenticatorAssertionResponseJSON `json:"response"`
}

// https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse
type AuthenticatorAssertionResponseJSON struct {
	AuthenticatorResponseJSON

	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
	AttestationObject string `json:"attestationObject"`
}

type PublicKeyData interface {
	Verify(data []byte, signature []byte) (bool, error)
}

type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse

	AuthenticatorData AuthenticatorData `json:"authenticatorData"`
	Signature         []byte            `json:"signature"`
	UserHandle        string            `json:"userHandle"`
	AttestationObject []byte            `json:"attestationObject"`
}

func (a AuthenticatorAssertionResponseJSON) Unmarshal() (*AuthenticatorAssertionResponse, error) {
	rawAuthData, err := Base64URLEncodedByte(a.AuthenticatorData).Decode()
	if err != nil {
		return nil, err
	}

	authData := AuthenticatorData{}
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

	attestationObject, err := Base64URLEncodedByte(a.AttestationObject).Decode()
	if err != nil {
		return nil, err
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
	}, nil
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

type publicKeyData struct {
	_         bool  `cbor:",keyasint" json:"public_key"`
	KeyType   int64 `cbor:"1,keyasint" json:"kty"` // required
	Algorithm int64 `cbor:"3,keyasint" json:"alg"` // required
}

// The credential public key encoded in COSE_Key format, using the CTAP2 canonical CBOR encoding form.
func (r *CredentialRecord) GetPublicKey() (*PublicKeyData, error) {
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

	switch pk.KeyType {
	}

	return pk, err
}
