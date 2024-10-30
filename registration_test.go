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
}
