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
	data, err := webauthn.Base64URLEncodedByte([]byte("PpZrl-Wqt-OFfBpyy2SraN1m7LT0GZORwGA7-6ujYkNFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIGuD5_b-VnJU4OaKH80zuUPCMcj6H93AGdPs4wvTzO3RpQECAyYgASFYIDWHNBRkxpeaKyko7ZTkLvlrfi6TjOCqf7Ctfv2kv9AUIlggHyeS4DL4Mks6vQ1ljWUkaQt9oH03wB0u5qWT4cg1xms")).Decode()
	require.NoError(t, err)
	err = authenticatorData.Unmarshal(data)
	require.NoError(t, err)

	rpID := "www.passkeys-debugger.io"
	rpIDHash := sha256.Sum256([]byte(rpID))

	assert.Equal(t, rpIDHash[:], authenticatorData.RPIDHash)

	flags := NewAuthenticatorFlags(t, []webauthn.AuthenticatorFlags{webauthn.FlagUserPresent, webauthn.FlagUserVerified, webauthn.FlagAttestedCredentialData})
	assert.Equal(t, flags, authenticatorData.Flags)

	assert.Equal(t, uint32(0), authenticatorData.SignCount)

	assert.Equal(t, "adce000235bcc60a648b0b25f1f05503", fmt.Sprintf("%x", authenticatorData.AttestedCredentialData.AAGUID))

	publickeyCredential, err := webauthn.Base64URLEncodedByte([]byte("a4Pn9v5WclTg5oofzTO5Q8IxyPof3cAZ0-zjC9PM7dE")).Decode()
	require.NoError(t, err)

	assert.Equal(t, uint16(len(publickeyCredential)), authenticatorData.AttestedCredentialData.CredentialIDLength)
	assert.Equal(t, publickeyCredential, authenticatorData.AttestedCredentialData.CredentialID)
}

func NewAuthenticatorFlags(t *testing.T, flags []webauthn.AuthenticatorFlags) webauthn.AuthenticatorFlags {
	t.Helper()

	var b byte
	for _, f := range flags {
		b |= byte(f)
	}
	return webauthn.AuthenticatorFlags(b)
}
