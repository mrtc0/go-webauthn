package webauthn_test

import (
	"testing"

	"github.com/mrtc0/go-webauthn"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticatorAttestationResponseJSON_Parse(t *testing.T) {
	t.Parallel()

	responseJSON := &webauthn.AuthenticatorAttestationResponseJSON{
		AttestationObject:  "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikPpZrl-Wqt-OFfBpyy2SraN1m7LT0GZORwGA7-6ujYkNFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIGuD5_b-VnJU4OaKH80zuUPCMcj6H93AGdPs4wvTzO3RpQECAyYgASFYIDWHNBRkxpeaKyko7ZTkLvlrfi6TjOCqf7Ctfv2kv9AUIlggHyeS4DL4Mks6vQ1ljWUkaQt9oH03wB0u5qWT4cg1xms",
		ClientDataJSON:     "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiLVlnQndvcG1hYkM3V0tBMUN2TjVhRjBqTUY5N2lYSUFVaFpiVkZwS2pDUSIsIm9yaWdpbiI6Imh0dHBzOi8vd3d3LnBhc3NrZXlzLWRlYnVnZ2VyLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
		Transports:         []string{"internal"},
		PublicKey:          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENYc0FGTGl5orKSjtlOQu-Wt-LpOM4Kp_sK1-_aS_0BQfJ5LgMvgySzq9DWWNZSRpC32gfTfAHS7mpZPhyDXGaw",
		PublicKeyAlgorithm: -7,
		AuthenticatorData:  "PpZrl-Wqt-OFfBpyy2SraN1m7LT0GZORwGA7-6ujYkNFAAAAAK3OAAI1vMYKZIsLJfHwVQMAIGuD5_b-VnJU4OaKH80zuUPCMcj6H93AGdPs4wvTzO3RpQECAyYgASFYIDWHNBRkxpeaKyko7ZTkLvlrfi6TjOCqf7Ctfv2kv9AUIlggHyeS4DL4Mks6vQ1ljWUkaQt9oH03wB0u5qWT4cg1xms",
	}

	response, err := responseJSON.Parse()
	assert.NoError(t, err)
	assert.Equal(t, "none", response.AttestationObject.Format)
}
