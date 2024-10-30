package webauthn_test

import (
	"testing"

	"github.com/mrtc0/go-webauthn"
	"github.com/stretchr/testify/assert"
)

func TestRelyingParty_CreateOptionsForRegistrationCelemony(t *testing.T) {
	t.Parallel()

	rpConfig := &webauthn.RPConfig{
		ID:              "example.com",
		Name:            "Example",
		Origin:          "https://example.com",
		SubFrameOrigins: []string{},
	}

	user := &webauthn.WebAuthnUser{
		ID:          []byte("123456789"),
		Name:        "morita",
		DisplayName: "Kohei Morita",
	}

	creationOptions, session, err := webauthn.NewRelyingParty(rpConfig).CreateOptionsForRegistrationCeremony(user)
	assert.NoError(t, err)

	assert.Equal(t, rpConfig.ID, creationOptions.RP.ID)
	assert.Equal(t, rpConfig.Name, creationOptions.RP.Name)
	assert.Equal(t, user.ID, creationOptions.User.ID)
	assert.Equal(t, user.Name, creationOptions.User.Name)
	assert.Equal(t, user.DisplayName, creationOptions.User.DisplayName)

	assert.Equal(t, rpConfig.Origin, session.RPID)
	assert.Equal(t, session.Challenge, creationOptions.Challenge.String())
	assert.GreaterOrEqual(t, len(session.Challenge), 16)

	t.Run("with options", func(t *testing.T) {
		testCases := map[string]struct {
			opt        webauthn.RegistrationCeremonyOption
			expectFunc func(t *testing.T, creationOptions *webauthn.PublicKeyCredentialCreationOptions)
		}{
			"WithAuthenticatorSelection": {
				opt: webauthn.WithAuthenticatorSelection(
					webauthn.AuthenticatorSelectionCriteria{
						AuthenticatorAttachment: "platform",
						ResidentKey:             "preferred",
						RequireResidentKey:      true,
						UserVerification:        "required",
					},
				),
				expectFunc: func(t *testing.T, creationOptions *webauthn.PublicKeyCredentialCreationOptions) {
					assert.Equal(t, "platform", creationOptions.AuthenticatorSelection.AuthenticatorAttachment)
					assert.Equal(t, "preferred", creationOptions.AuthenticatorSelection.ResidentKey)
					assert.True(t, creationOptions.AuthenticatorSelection.RequireResidentKey)
					assert.Equal(t, "required", creationOptions.AuthenticatorSelection.UserVerification)
				},
			},
		}

		for name, tc := range testCases {
			tc := tc
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				rp := webauthn.NewRelyingParty(rpConfig)
				creationOptions, _, err := rp.CreateOptionsForRegistrationCeremony(user, tc.opt)
				assert.NoError(t, err)
				tc.expectFunc(t, creationOptions)
			})
		}
	})
}
