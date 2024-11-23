package webauthn

import (
	"fmt"
)

// https://www.iana.org/assignments/webauthn/webauthn.xhtml
type AttestationFormat string

const (
	// https://www.iana.org/assignments/webauthn/webauthn.xhtml
	// AttestationFormatPacked is the "packed" attestation statement format is a WebAuthn-optimized format for attestation.
	// It uses a very compact but still extensible encoding method. This format is implementable by authenticators with limited resources (e.g., secure elements).
	AttestationFormatPacked AttestationFormat = "packed"

	// AttestationFormatTPM is the TPM attestation statement format returns an attestation statement in the same format as the packed
	// attestation statement format, although the rawData and signature fields are computed differently.
	AttestationFormatTPM AttestationFormat = "tpm"

	// AttestationFormatAndroidKey is platform authenticators on versions "N", and later, may provide this proprietary "hardware attestation" statement.
	AttestationFormatAndroidKey AttestationFormat = "android-key"

	// AttestationFormatAndroidSafetyNet is Android-based platform authenticators MAY produce an attestation statement based on the Android SafetyNet API.
	AttestationFormatAndroidSafetyNet AttestationFormat = "android-safetynet"

	// AttestationFormatFIDOUniversalSecondFactor is used with FIDO U2F authenticators
	AttestationFormatFIDOUniversalSecondFactor AttestationFormat = "fido-u2f"

	// AttestationFormatApple is used with Apple devices' platform authenticators
	AttestationFormatApple AttestationFormat = "apple"

	// AttestationFormatNone is used to replace any authenticator-provided attestation statement when a WebAuthn Relying Party indicates it does not wish to receive attestation information.
	AttestationFormatNone AttestationFormat = "none"
)

type AttestationStatementVerifier interface {
	// https://www.w3.org/TR/webauthn-3/#sctn-attestation-formats
	Verify() (attestationType string, x509Certs []string, err error)
}

// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
type PackedAttestationStatementVerifier struct {
	AttStmt        map[string]any
	AuthData       []byte
	ClientDataHash []byte
}

func (p *PackedAttestationStatementVerifier) Verify() (attestationType string, x509Certs []string, err error) {
	// 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
	alg, exists := p.AttStmt["alg"].(int64)
	if !exists {
		return "", nil, fmt.Errorf("attestation statement missing alg")
	}

	sig, exists := p.AttStmt["sig"].([]byte)
	if !exists {
		return "", nil, fmt.Errorf("attestation statement missing sig")
	}

	_, exists = p.AttStmt["x5c"].([]any)
	if exists {
		// TODO: support x5c
		return "", nil, fmt.Errorf("unsupported x5c")
	}

	// 3. If x5c is not present, self attestation is in use.
	valid, err := p.verifySelfAttestation(alg, sig)
	if err != nil {
		return "", nil, fmt.Errorf("failed to verify self attestation: %w", err)
	}

	if !valid {
		return "", nil, fmt.Errorf("invalid signature")
	}

	return "Self", nil, nil
}

func (p *PackedAttestationStatementVerifier) verifySelfAttestation(alg int64, sig []byte) (bool, error) {
	authenticatorData := AuthenticatorData{}
	if err := authenticatorData.Unmarshal(p.AuthData); err != nil {
		return false, fmt.Errorf("failed to unmarshal authenticator data: %w", err)
	}

	// 3-1. Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
	param := []PublicKeyCredentialParameters{
		{
			Type: PublicKeyCredentialTypePublicKey,
			Alg:  COSEAlgorithmIdentifier(alg),
		},
	}
	if err := authenticatorData.AttestedCredentialData.VerifyPublicKeyAlgParams(param); err != nil {
		return false, fmt.Errorf("failed to verify public key algorithm: %w", err)
	}

	pubkey, err := ParsePublicKey(authenticatorData.AttestedCredentialData.CredentialPublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	// 3-2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.
	verificationData := append(p.AuthData, p.ClientDataHash...)

	return pubkey.Verify(verificationData, sig)
}

type TPMAttestationStatementVerifier struct{}

func (t *TPMAttestationStatementVerifier) Verify() (attestationType string, x509Certs []string, err error) {
	panic("not implemented")
}

type AndroidKeyAttestationStatementVerifier struct{}

func (a *AndroidKeyAttestationStatementVerifier) Verify() (attestationType string, x509Certs []string, err error) {
	panic("not implemented")
}

type AndroidSafetyNetAttestationStatementVerifier struct{}

func (a *AndroidSafetyNetAttestationStatementVerifier) Verify() (attestationType string, x509Certs []string, err error) {
	panic("not implemented")
}

type FIDOUniversalSecondFactorAttestationStatementVerifier struct{}

func (f *FIDOUniversalSecondFactorAttestationStatementVerifier) Verify() (attestationType string, x509Certs []string, err error) {
	panic("not implemented")
}

type AppleAttestationStatementVerifier struct{}

func (a *AppleAttestationStatementVerifier) Verify() (attestationType string, x509Certs []string, err error) {
	panic("not implemented")
}

// https://www.w3.org/TR/webauthn-3/#sctn-none-attestation
type NoneAttestationStatementVerifier struct{}

func (n *NoneAttestationStatementVerifier) Verify() (attestationType string, x509Certs []string, err error) {
	return "None", []string{}, nil
}

func DetermineAttestaionStatement(format string, attStmt map[string]any, authData, hash []byte) (AttestationStatementVerifier, error) {
	// passkeys always uses the "none" attestation format
	// ref. https://forums.developer.apple.com/forums/thread/742434
	switch AttestationFormat(format) {
	case AttestationFormatPacked:
		return &PackedAttestationStatementVerifier{}, nil
	case AttestationFormatTPM:
		return &TPMAttestationStatementVerifier{}, nil
	case AttestationFormatAndroidKey:
		return &AndroidKeyAttestationStatementVerifier{}, nil
	case AttestationFormatAndroidSafetyNet:
		return &AndroidSafetyNetAttestationStatementVerifier{}, nil
	case AttestationFormatFIDOUniversalSecondFactor:
		return &FIDOUniversalSecondFactorAttestationStatementVerifier{}, nil
	case AttestationFormatApple:
		return &AppleAttestationStatementVerifier{}, nil
	case AttestationFormatNone:
		return &NoneAttestationStatementVerifier{}, nil
	default:
		return nil, fmt.Errorf("unsupported attestation format: %s", format)
	}
}
