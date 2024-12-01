package main

import "github.com/mrtc0/go-webauthn"

type UserSessionRepository interface {
	CreateUserSession(session *UserSession) error
	FindUserSessionByID(id string) (*UserSession, error)
}

type PasskeySessionRepository interface {
	CreatePasskeySession(session *PasskeySession) error
	FindByID(ID string) (*PasskeySession, error)
	DeleteByID(ID string) error
}

type UserSession struct {
	ID     string
	UserID string
}

type PasskeySession struct {
	ID                 string
	WebAuthnSessionID  []byte
	Challenge          []byte
	RPID               string
	UserVerification   webauthn.UserVerification
	AllowedCredentials []webauthn.PublicKeyCredentialDescriptor
}

func NewUserSession(userID string) *UserSession {
	return &UserSession{
		ID:     GenerateID(),
		UserID: userID,
	}
}

func NewPasskeySession(id string, webauthnSession *webauthn.Session) *PasskeySession {
	return &PasskeySession{
		ID:                 id,
		WebAuthnSessionID:  webauthnSession.ID,
		Challenge:          webauthnSession.Challenge,
		RPID:               webauthnSession.RPID,
		UserVerification:   webauthnSession.UserVerification,
		AllowedCredentials: webauthnSession.AllowedCredentials,
	}
}

func (p *PasskeySession) ToWebAuthnSession() *webauthn.Session {
	return &webauthn.Session{
		ID:                 p.WebAuthnSessionID,
		Challenge:          p.Challenge,
		RPID:               p.RPID,
		UserVerification:   p.UserVerification,
		AllowedCredentials: p.AllowedCredentials,
	}
}
