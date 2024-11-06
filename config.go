package webauthn

import "time"

var defaultTimeout = (time.Second * 120).Milliseconds()

type RPConfig struct {
	ID              string
	Name            string
	Origins         []string
	SubFrameOrigins []string
}

type RelyingParty struct {
	RPConfig *RPConfig
}

type WebAuthnUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []CredentialRecord
}

func NewRelyingParty(rp *RPConfig) *RelyingParty {
	return &RelyingParty{RPConfig: rp}
}
