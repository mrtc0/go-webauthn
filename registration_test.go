package webauthn_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mrtc0/go-webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestRelyingParty_CreateCredential(t *testing.T) {
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

	rp := webauthn.NewRelyingParty(rpConfig)
	_, session, err := rp.CreateOptionsForRegistrationCeremony(user)
	require.NoError(t, err)

	testCases := map[string]struct {
		user       *webauthn.WebAuthnUser
		session    *webauthn.Session
		credential *webauthn.RegistrationResponseJSON
		err        error
	}{
		"NG: mismatch user": {
			user: &webauthn.WebAuthnUser{
				ID:          []byte("987654321"),
				Name:        "morita",
				DisplayName: "Kohei Morita",
			},
			session:    session,
			credential: nil,
			err:        fmt.Errorf("mismatch UserID"),
		},
		"NG: invalid credential response": {
			user:    user,
			session: session,
			credential: &webauthn.RegistrationResponseJSON{
				Response: webauthn.AuthenticatorAttestationResponseJSON{},
			},
			err: fmt.Errorf("failed to parse client data JSON"),
		},
		"NG: mismatch challenge": {
			user:    user,
			session: session,
			credential: &webauthn.RegistrationResponseJSON{
				ID: "123456789",
				Response: webauthn.AuthenticatorAttestationResponseJSON{
					ClientDataJSON: generateClientDataJSON(t, rpConfig.Origin, "invalid challenge"),
				},
			},
			err: fmt.Errorf("challenge mismatch"),
		},
		"NG: mismatch origin": {
			user:    user,
			session: session,
			credential: &webauthn.RegistrationResponseJSON{
				ID: "123456789",
				Response: webauthn.AuthenticatorAttestationResponseJSON{
					ClientDataJSON: generateClientDataJSON(t, "https://invalid.com", string(session.Challenge)),
				},
			},
			err: fmt.Errorf("origin mismatch"),
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := rp.CreateCredential(tc.session, tc.credential)
			if tc.err != nil {
				assert.ErrorContains(t, err, tc.err.Error())
				return
			}

			assert.NoError(t, err)
		})
	}
}

func generateClientDataJSON(t *testing.T, origin, challenge string) string {
	t.Helper()

	clientDataJson := &webauthn.CollectedClientData{
		Type:      "webauthn.create",
		Challenge: challenge,
		Origin:    origin,
	}

	data, err := json.Marshal(clientDataJson)
	require.NoError(t, err)

	return webauthn.Base64URLEncodedByte(data).String()
}
