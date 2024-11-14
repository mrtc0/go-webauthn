package testutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/mrtc0/go-webauthn"
)

func NewRegistrationCelemonyResponse(
	rpID string,
	challenge []byte,
	flags webauthn.AuthenticatorFlags,
	attestationFormat string,
) (*webauthn.RegistrationResponseJSON, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	publicKey := privateKey.PublicKey
	ec2PublicKeyData := webauthn.EC2PublicKeyData{
		PublicKeyDataBase: webauthn.PublicKeyDataBase{
			KeyType:   2,
			Algorithm: -7,
		},
		Curve:       1,
		XCoordinate: publicKey.X.Bytes(),
		YCoordinate: publicKey.Y.Bytes(),
	}
	encodedPublicKey, err := cbor.Marshal(ec2PublicKeyData)
	if err != nil {
		return nil, err
	}

	authenticatorData := NewAuthenticatorData(rpID, flags, encodedPublicKey)

	var attestationObjectBytes []byte
	switch attestationFormat {
	case "none":
		attestationObjectBytes, err = NewAttestationObjectNone(authenticatorData)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported attestation format: %s", attestationFormat)
	}

	clientDataJSON := webauthn.CollectedClientData{
		Type:        "webauthn.create",
		Challenge:   webauthn.Base64URLEncodedByte(challenge).String(),
		Origin:      "https://example.com",
		CrossOrigin: false,
	}
	clientDataJSONByte, err := json.Marshal(clientDataJSON)
	if err != nil {
		return nil, err
	}

	return &webauthn.RegistrationResponseJSON{
		ID:                     webauthn.Base64URLEncodedByte([]byte("credential-id")).String(),
		RawID:                  webauthn.Base64URLEncodedByte([]byte("credential-id")).String(),
		Type:                   "public-key",
		ClientExtensionResults: webauthn.AuthenticationExtensionsClientOutputsJSON{},
		Response: webauthn.AuthenticatorAttestationResponseJSON{
			AttestationObject:  webauthn.Base64URLEncodedByte(attestationObjectBytes).String(),
			ClientDataJSON:     webauthn.Base64URLEncodedByte(clientDataJSONByte).String(),
			Transports:         []string{"internal"},
			AuthenticatorData:  webauthn.Base64URLEncodedByte(authenticatorData).String(),
			PublicKey:          webauthn.Base64URLEncodedByte(encodedPublicKey).String(),
			PublicKeyAlgorithm: -7,
		},
	}, nil

}

func NewAttestationObjectNone(authenticatorData []byte) ([]byte, error) {
	attestatioObject := webauthn.AttestationObject{
		Format:       "none",
		AuthData:     authenticatorData,
		AttStatement: nil,
	}

	attestationObjectBytes, err := cbor.Marshal(attestatioObject)
	if err != nil {
		return nil, err
	}

	return attestationObjectBytes, nil
}

func NewAuthenticatorData(
	rpID string,
	flags webauthn.AuthenticatorFlags,
	publicKey []byte,
) []byte {
	var authenticatorData []byte

	rpIDHash := sha256.Sum256([]byte(rpID))
	authenticatorData = append(authenticatorData, rpIDHash[:]...)

	authenticatorData = append(authenticatorData, byte(flags))

	signCount := uint32(0)
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, signCount)
	authenticatorData = append(authenticatorData, bs...)

	aaguid := make([]byte, 16)
	_, err := rand.Read(aaguid)
	if err != nil {
		panic(err)
	}
	authenticatorData = append(authenticatorData, aaguid...)

	credentialID := []byte("credential-id")
	credentialIDLength := uint16(len(credentialID))

	bs = make([]byte, 2)
	binary.BigEndian.PutUint16(bs, credentialIDLength)
	authenticatorData = append(authenticatorData, bs...)
	authenticatorData = append(authenticatorData, credentialID...)

	authenticatorData = append(authenticatorData, publicKey...)

	// TODO: Add extensions

	return authenticatorData
}
