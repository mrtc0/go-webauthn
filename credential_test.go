package webauthn_test

import (
	"testing"

	"github.com/mrtc0/go-webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialRecord_GetPublicKey(t *testing.T) {
	t.Parallel()

	publicKey, err := webauthn.Base64URLEncodedByte([]byte(testDataCredentialPublicKey)).Decode()
	require.NoError(t, err)

	credentialRecord := &webauthn.CredentialRecord{
		Type:      "public-key",
		PublicKey: publicKey,
	}

	publicKeyData, err := credentialRecord.GetPublicKey()
	require.NoError(t, err)

	assert.Equal(t, webauthn.COSEKeyTypeEC2, webauthn.COSEKeyType(publicKeyData.GetKeyType()))
	assert.Equal(t, webauthn.AlgES256, webauthn.COSEAlgorithmIdentifier(publicKeyData.GetAlgorithm()))
}
