package webauthn

import "encoding/json"

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

// https://www.w3.org/TR/webauthn-3/#client-data
type CollectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	TopOrigin   string `json:"topOrigin,omitempty"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

func ParseClientDataJSON(clientDataJSON Base64URLEncodedByte) (*CollectedClientData, error) {
	var c CollectedClientData

	data, err := clientDataJSON.Decode()
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *CollectedClientData) IsRegistrationCelemoney() bool {
	return c.Type == "webauthn.create"
}
