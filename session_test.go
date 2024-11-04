package webauthn_test

import (
	"testing"

	"github.com/mrtc0/go-webauthn"
)

func TestNewWebAuthnSession(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		challenge        []byte
		userVerification webauthn.UserVerification
	}{
		"ok: valid session values": {
			challenge:        []byte("1234567890123456"),
			userVerification: webauthn.UserVerificationRequired,
		},
		"ng: invalid challenge (too short)": {
			challenge:        []byte("123456"),
			userVerification: webauthn.UserVerificationPreferred,
		},
		"ng: invalid userVerification": {
			challenge:        []byte("1234567890123456"),
			userVerification: "invalid",
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := webauthn.NewWebAuthnSession([]byte("id"), tc.challenge, "rp", tc.userVerification, nil)
			if err != nil {
				return
			}
		})
	}

}
