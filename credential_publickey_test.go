package webauthn_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/mrtc0/go-webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEC2PublicKeyData_Verify(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		algorithm webauthn.COSEAlgorithmIdentifier
		hasher    crypto.Hash
		curve     elliptic.Curve
		expect    bool
	}{
		"ES256": {
			algorithm: webauthn.AlgES256,
			hasher:    crypto.SHA256,
			curve:     elliptic.P256(),
			expect:    true,
		},
		"ES384": {
			algorithm: webauthn.AlgES384,
			hasher:    crypto.SHA384,
			curve:     elliptic.P384(),
			expect:    true,
		},
		"ES512": {
			algorithm: webauthn.AlgES512,
			hasher:    crypto.SHA512,
			curve:     elliptic.P521(),
			expect:    true,
		},
		"unsupported: PS256": {
			algorithm: webauthn.AlgPS256,
			hasher:    crypto.SHA256,
			curve:     elliptic.P256(),
			expect:    false,
		},
	}

	for name, tc := range testCases {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data := []byte("ABCD1234")
			hasher := tc.hasher.New()
			hasher.Write(data)

			privateKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			publicKey := privateKey.PublicKey

			sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hasher.Sum(nil))
			require.NoError(t, err)

			ec2PublicKeyData := webauthn.EC2PublicKeyData{
				PublicKeyDataBase: webauthn.PublicKeyDataBase{
					KeyType:   int64(webauthn.COSEKeyTypeEC2),
					Algorithm: int64(tc.algorithm),
				},
				Curve:       1,
				XCoordinate: publicKey.X.Bytes(),
				YCoordinate: publicKey.Y.Bytes(),
			}

			valid, err := ec2PublicKeyData.Verify(data, sig)
			if tc.expect {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}

			assert.Equal(t, tc.expect, valid)

			valid, _ = ec2PublicKeyData.Verify([]byte("1234ABCD"), sig)
			assert.Equal(t, false, valid)
		})
	}
}
