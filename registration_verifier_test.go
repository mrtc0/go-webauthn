package webauthn_test

import (
	"testing"

	"github.com/mrtc0/go-webauthn"
	"github.com/mrtc0/go-webauthn/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistrationCelemonyVerifier_VerifyRPID(t *testing.T) {
	t.Parallel()

	registrationResponse := testutils.NewRegistrationCelemonyResponse(
		t,
		"example.com",
		[]byte("123456789"),
		webauthn.FlagUserPresent|webauthn.FlagUserVerified|webauthn.FlagAttestedCredentialData,
		"none",
	)

	testCases := map[string]struct {
		rpID   string
		expect bool
	}{
		"OK: same rpID": {
			rpID:   "example.com",
			expect: true,
		},
		"NG: different rpID": {
			rpID:   "example.jp",
			expect: false,
		},
	}

	for name, tc := range testCases {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verifier, err := webauthn.NewRegistrationCelemonyVerifier(*registrationResponse)
			require.NoError(t, err)

			actual, err := verifier.VerifyRPID(tc.rpID)
			assert.Equal(t, tc.expect, actual)
			if tc.expect {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}

}
