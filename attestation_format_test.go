package webauthn_test

import (
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/mrtc0/go-webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	packedAttestationObject         = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgeB30aTKJQZUpFt6k6fMUZjUX0xDaPQNySL21XYuXUt8CIQCujJwAe8P1ON42dXjIuK1Np9pjZLwaHB8k6Yb7mWeoCmhhdXRoRGF0YVikPpZrl-Wqt-OFfBpyy2SraN1m7LT0GZORwGA7-6ujYkNFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIOwc9pv0iTXKEB_K_PXFGIzNh_0VuP60JbTUYkwDzOMVpQECAyYgASFYIIvFBn-o31Xr8nqwKa2giVbN4Um5mZYovI6ZXUSPvbWGIlggItUgAftgDCGu7ybCkr_J_I2YOX5V50-cxetqgWqKYZo"
	packedAttestationClientDataJSON = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTjdEM3ppM2J0YjdGeTBTQ25MZFFHbmdBMHZ2d2hLd0pwRG5nMWtMTFd2RSIsIm9yaWdpbiI6Imh0dHBzOi8vd3d3LnBhc3NrZXlzLWRlYnVnZ2VyLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
)

func TestPackedAttestationStatementVerifier_Verify(t *testing.T) {
	t.Parallel()

	rawAttestationObject, err := webauthn.Base64URLEncodedByte(packedAttestationObject).Decode()
	require.NoError(t, err)

	clientDataJSON, err := webauthn.Base64URLEncodedByte(packedAttestationClientDataJSON).Decode()
	require.NoError(t, err)

	sum := sha256.Sum256(clientDataJSON)
	hash := sum[:]

	attestationObject := webauthn.AttestationObject{}
	require.NoError(t, cbor.Unmarshal(rawAttestationObject, &attestationObject))

	verifier := &webauthn.PackedAttestationStatementVerifier{
		AttStmt:        attestationObject.AttStatement,
		AuthData:       attestationObject.AuthData,
		ClientDataHash: hash,
	}

	_, _, err = verifier.Verify()
	assert.NoError(t, err)
}
