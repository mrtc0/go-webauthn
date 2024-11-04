package webauthn

import "fmt"

// CollectedClientData represents the contextual bindings of both the WebAuthn Relying Party and the client.
// https://www.w3.org/TR/webauthn-3/#dictionary-client-data
type CollectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	TopOrigin   string `json:"topOrigin,omitempty"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

func (c *CollectedClientData) IsRegistrationCelemoney() bool {
	return c.Type == "webauthn.create"
}

func (c *CollectedClientData) IsAuthenticationCeremony() bool {
	return c.Type == "webauthn.get"
}

func (c *CollectedClientData) IsValidOrigin(rpOrigins []string, rpSubFrameOrigins []string) (bool, error) {
	found := false
	for _, rpOrigin := range rpOrigins {
		if c.Origin == rpOrigin {
			found = true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("origin mismatch. expected: %s, got: %s", rpOrigins, c.Origin)
	}

	if c.TopOrigin != "" {
		if !c.CrossOrigin {
			return false, fmt.Errorf("topOrigin present, but crossOrigin is false")
		}

		if len(rpSubFrameOrigins) > 0 {
			found := false

			for _, rpTopOrigin := range rpSubFrameOrigins {
				if c.TopOrigin == rpTopOrigin {
					found = true
					break
				}
			}

			if !found {
				return false, fmt.Errorf("top origin not found in RP cross origins")
			}
		}
	}

	return true, nil
}
