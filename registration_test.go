package webauthn_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mrtc0/go-webauthn"
	"github.com/mrtc0/go-webauthn/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateRegistrationCelemonyOptions(t *testing.T) {
	t.Parallel()

	rpConfig := &webauthn.RPConfig{
		ID:              "example.com",
		Name:            "Example",
		Origins:         []string{"https://example.com"},
		SubFrameOrigins: []string{},
	}

	user := &webauthn.WebAuthnUser{
		ID:          []byte("123456789"),
		Name:        "morita",
		DisplayName: "Kohei Morita",
	}

	testCases := map[string]struct {
		opts   webauthn.RegistrationCeremonyOption
		expect webauthn.PublicKeyCredentialCreationOptions
	}{
		"WithAuthenticatorSelection": {
			opts: webauthn.WithAuthenticatorSelection(
				webauthn.AuthenticatorSelectionCriteria{
					ResidentKey:        "required",
					RequireResidentKey: true,
					UserVerification:   webauthn.UserVerificationRequired,
				},
			),
			expect: webauthn.PublicKeyCredentialCreationOptions{
				AuthenticatorSelection: webauthn.AuthenticatorSelectionCriteria{
					ResidentKey:        "required",
					RequireResidentKey: true,
					UserVerification:   webauthn.UserVerificationRequired,
				},
				Attestation: webauthn.AttestationConveyancePreferenceNone,
			},
		},
		"WithAttestationPreference": {
			opts: webauthn.WithAttestationPreference(webauthn.AttestationConveyancePreferenceDirect),
			expect: webauthn.PublicKeyCredentialCreationOptions{
				AuthenticatorSelection: webauthn.AuthenticatorSelectionCriteria{
					ResidentKey:        "required",
					RequireResidentKey: true,
					UserVerification:   webauthn.UserVerificationPreferred,
				},
				Attestation: webauthn.AttestationConveyancePreferenceDirect,
			},
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			creationOptions, _, err := webauthn.CreateRegistrationCeremonyOptions(*rpConfig, *user, tc.opts)
			require.NoError(t, err)

			opt := cmpopts.IgnoreFields(
				webauthn.PublicKeyCredentialCreationOptions{},
				"RP", "User", "Challenge", "PubKeyCredParams", "Timeout", "ExcludeCredentials",
			)

			if diff := cmp.Diff(tc.expect, *creationOptions, opt); diff != "" {
				t.Errorf("(-got, +want)\n%s", diff)
			}
		})
	}

	t.Run("Test session values", func(t *testing.T) {
		t.Parallel()

		creationOptions, session, err := webauthn.CreateRegistrationCeremonyOptions(*rpConfig, *user)
		require.NoError(t, err)

		assert.Equal(t, creationOptions.User.ID, session.ID)
		assert.Equal(t, rpConfig.ID, session.RPID)
		assert.Equal(t, creationOptions.Challenge, webauthn.Base64URLEncodedByte(session.Challenge))
	})
}

func TestVerifyRegistrationCelemonyResponse(t *testing.T) {
	t.Parallel()

	rpConfig := &webauthn.RPConfig{
		ID:              "example.com",
		Name:            "Relying Party Name",
		Origins:         []string{"https://example.com"},
		SubFrameOrigins: []string{},
	}

	user := &webauthn.WebAuthnUser{
		ID:          []byte("nBhwlkrGyS_mazQe4dtUlIH9-sI6EMX8ZWQdgDea35I"),
		Name:        "test",
		DisplayName: "test",
	}

	_, session, err := webauthn.CreateRegistrationCeremonyOptions(*rpConfig, *user)
	require.NoError(t, err)
	challenge := []byte("-YgBwopmabC7WKA1CvN5aF0jMF97iXIAUhZbVFpKjCQ")
	c, err := webauthn.Base64URLEncodedByte(challenge).Decode()
	require.NoError(t, err)
	session.Challenge = c

	registrationResponse, err := testutils.NewRegistrationCelemonyResponse(
		"example.com",
		c,
		webauthn.FlagUserPresent|webauthn.FlagUserVerified|webauthn.FlagAttestedCredentialData,
		"none",
	)
	require.NoError(t, err)

	_, err = webauthn.VerifyRegistrationCelemonyResponse(*rpConfig, *session, *registrationResponse, nil)
	assert.NoError(t, err)
}
