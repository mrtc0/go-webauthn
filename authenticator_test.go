package webauthn_test

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/mrtc0/go-webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticatorFlags_HasUserPresent(t *testing.T) {
	flags := NewAuthenticatorFlags(t, []webauthn.AuthenticatorFlags{webauthn.FlagUserPresent})
	assert.Equal(t, true, flags.HasUserPresent())

	flags = NewAuthenticatorFlags(t, []webauthn.AuthenticatorFlags{webauthn.FlagUserVerified})
	assert.Equal(t, false, flags.HasUserPresent())

	flags = NewAuthenticatorFlags(t, []webauthn.AuthenticatorFlags{webauthn.FlagUserPresent, webauthn.FlagUserVerified})
	assert.Equal(t, true, flags.HasUserPresent())
}

func TestAuthenticatorData_Unmarshal(t *testing.T) {
	authenticatorData := &webauthn.AuthenticatorData{}
	data, err := webauthn.Base64URLEncodedByte([]byte(testDataAuthenticatorData)).Decode()
	require.NoError(t, err)
	err = authenticatorData.Unmarshal(data)
	require.NoError(t, err)

	rpID := "www.passkeys-debugger.io"
	rpIDHash := sha256.Sum256([]byte(rpID))

	assert.Equal(t, rpIDHash[:], authenticatorData.RPIDHash)

	flags := NewAuthenticatorFlags(t, []webauthn.AuthenticatorFlags{
		webauthn.FlagUserPresent, webauthn.FlagUserVerified, webauthn.FlagAttestedCredentialData, webauthn.FlagBackupEligible, webauthn.FlagBackupState,
	})
	assert.Equal(t, flags, authenticatorData.Flags)

	assert.Equal(t, uint32(0), authenticatorData.SignCount)

	assert.Equal(t, "fbfc3007154e4ecc8c0b6e020557d7bd", fmt.Sprintf("%x", authenticatorData.AttestedCredentialData.AAGUID))

	publickeyCredentialID, err := webauthn.Base64URLEncodedByte([]byte("JKZbixUfKN_aZtimefYT-OjH5dw")).Decode()
	require.NoError(t, err)

	assert.Equal(t, uint16(len(publickeyCredentialID)), authenticatorData.AttestedCredentialData.CredentialIDLength)
	assert.Equal(t, publickeyCredentialID, authenticatorData.AttestedCredentialData.CredentialID)
}

func NewAuthenticatorFlags(t *testing.T, flags []webauthn.AuthenticatorFlags) webauthn.AuthenticatorFlags {
	t.Helper()

	var b byte
	for _, f := range flags {
		b |= byte(f)
	}
	return webauthn.AuthenticatorFlags(b)
}
