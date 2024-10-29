package webauthn

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
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

type PackedAttestationStatementVerifier struct{}

func (p *PackedAttestationStatementVerifier) Verify() (attestationType string, x509Certs []string, err error) {
	panic("not implemented")
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

func DetermineAttestaionStatement(format string, attStmt cbor.RawMessage, authData, hash []byte) (AttestationStatementVerifier, error) {
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
