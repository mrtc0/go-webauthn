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

func TestRegistrationCelemonyVerifier_VerifyAuthenticatorDataFlags(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		userVerification   webauthn.UserVerification
		authenticatorFlags webauthn.AuthenticatorFlags
		expect             bool
	}{
		"NG: UserPresent flag is not set": {
			userVerification:   webauthn.UserVerificationRequired,
			authenticatorFlags: webauthn.FlagUserVerified | webauthn.FlagAttestedCredentialData,
			expect:             false,
		},
		"NG: userVerification is required, but UserVerified flag is not set": {
			userVerification:   webauthn.UserVerificationRequired,
			authenticatorFlags: webauthn.FlagUserPresent | webauthn.FlagAttestedCredentialData,
			expect:             false,
		},
		"NG: BackupEligible flag is not set, but BackupState flag is set": {
			userVerification:   webauthn.UserVerificationRequired,
			authenticatorFlags: webauthn.FlagUserPresent | webauthn.FlagUserVerified | webauthn.FlagAttestedCredentialData | webauthn.FlagBackupState,
			expect:             false,
		},
		"OK: valid flags": {
			userVerification:   webauthn.UserVerificationRequired,
			authenticatorFlags: webauthn.FlagUserPresent | webauthn.FlagUserVerified | webauthn.FlagAttestedCredentialData | webauthn.FlagBackupEligible | webauthn.FlagBackupState,
			expect:             true,
		},
	}

	for name, tc := range testCases {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			registrationResponse := testutils.NewRegistrationCelemonyResponse(
				t,
				"example.com",
				[]byte("123456789"),
				tc.authenticatorFlags,
				"none",
			)

			verifier, err := webauthn.NewRegistrationCelemonyVerifier(*registrationResponse)
			require.NoError(t, err)

			actual, err := verifier.VerifyAuthenticatorDataFlags(tc.userVerification)
			assert.Equal(t, tc.expect, actual)

			if tc.expect {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestRegistrationCelemonyVerifier_VerifyPublicKeyAlgParams(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		params []webauthn.PublicKeyCredentialParameters
		expect bool
	}{
		"OK: valid alg param": {
			params: []webauthn.PublicKeyCredentialParameters{
				{
					Type: webauthn.PublicKeyCredentialTypePublicKey,
					Alg:  webauthn.AlgES256,
				},
			},
			expect: true,
		},
		"NG: invalid arg param": {
			params: []webauthn.PublicKeyCredentialParameters{
				{
					Type: webauthn.PublicKeyCredentialTypePublicKey,
					Alg:  webauthn.AlgES384,
				},
			},
		},
	}

	for name, tc := range testCases {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			registrationResponse := testutils.NewRegistrationCelemonyResponse(
				t,
				"example.com",
				[]byte("123456789"),
				webauthn.FlagUserPresent|webauthn.FlagUserVerified|webauthn.FlagAttestedCredentialData,
				"none",
			)

			verifier, err := webauthn.NewRegistrationCelemonyVerifier(*registrationResponse)
			require.NoError(t, err)

			actual, err := verifier.VerifyPublicKeyAlgParams(tc.params)
			assert.Equal(t, tc.expect, actual)

			if tc.expect {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
