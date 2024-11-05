package webauthn_test

import (
	"testing"

	"github.com/mrtc0/go-webauthn"
	"github.com/stretchr/testify/assert"
)

func TestCollectedClientData_IsValidOrigin(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		rpOrigins         []string
		rpSubFrameOrigins []string
		ccd               *webauthn.CollectedClientData
		expected          bool
	}{
		"OK: same origin": {
			rpOrigins:         []string{"https://example.com"},
			rpSubFrameOrigins: []string{},
			ccd: &webauthn.CollectedClientData{
				Origin: "https://example.com",
			},
			expected: true,
		},
		"NG: different origin": {
			rpOrigins:         []string{"https://example.com"},
			rpSubFrameOrigins: []string{},
			ccd: &webauthn.CollectedClientData{
				Origin: "https://example.jp",
			},
			expected: false,
		},
		"OK: expected top-level origin": {
			rpOrigins:         []string{"https://example.com", "https://example-partner1.org"},
			rpSubFrameOrigins: []string{"https://example.com", "https://example-partner1.org"},
			ccd: &webauthn.CollectedClientData{
				Origin:      "https://example.com",
				TopOrigin:   "https://example-partner1.org",
				CrossOrigin: true,
			},
			expected: true,
		},
		"NG: unexpected top-level origin": {
			rpOrigins:         []string{"https://example.com"},
			rpSubFrameOrigins: []string{"https://example.com"},
			ccd: &webauthn.CollectedClientData{
				Origin:      "https://example.com",
				TopOrigin:   "https://cross-frame.example.jp",
				CrossOrigin: true,
			},
			expected: false,
		},
	}

	for name, tc := range testCases {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual, err := tc.ccd.IsValidOrigin(tc.rpOrigins, tc.rpSubFrameOrigins)
			if tc.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
			assert.Equal(t, tc.expected, actual)
		})
	}

}

func TestCollectedClientData_VerifyChallenge(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		ccd       *webauthn.CollectedClientData
		challenge []byte
		expected  bool
	}{
		"OK: same challenge": {
			ccd: &webauthn.CollectedClientData{
				Challenge: "dGhpc2lzY2hhbGxlbmdl",
			},
			challenge: []byte("thisischallenge"),
			expected:  true,
		},
		"NG: different challenge": {
			ccd: &webauthn.CollectedClientData{
				Challenge: "dGhpc2lzY2hhbGxlbmdl",
			},
			challenge: []byte("THISISCHALLENGE"),
			expected:  false,
		},
	}

	for name, tc := range testCases {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actual, err := tc.ccd.VerifyChallenge(tc.challenge)
			if tc.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
			assert.Equal(t, tc.expected, actual)
		})
	}
}
