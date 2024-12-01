package main

import (
	"bytes"
	"fmt"

	"github.com/Code-Hex/dd/p"
	"github.com/mrtc0/go-webauthn"
)

type UsersService interface {
	Signup(email, password string) error
	LoginWithPassword(email, password string) (*User, *UserSession, error)
	CurrentUser(sessionID string) (*User, error)
	// Passkeys Functions
	CreatePasskeyRegistrationOptions(rpConfig webauthn.RPConfig, userSessionID string, user User) (*webauthn.PublicKeyCredentialCreationOptions, *PasskeySession, error)
	PasskeyRegistration(rpConfig webauthn.RPConfig, user User, userSessionID string, registrationResponse webauthn.RegistrationResponseJSON) error
	CreatePasskeyAuthenticationOptions(rpConfig webauthn.RPConfig) (*webauthn.PublicKeyCredentialRequestOptions, *PasskeySession, error)
	LoginWithPasskey(rpConfig webauthn.RPConfig, passkeySessionID string, response webauthn.AuthenticationResponseJSON) (*User, *UserSession, error)
}

type usersService struct {
	userRepository           UserRepository
	userSessionRepository    UserSessionRepository
	passkeySessionRepository PasskeySessionRepository
	userPasskeyRepository    UserPasskeyRepository
}

func (u *usersService) Signup(email, password string) error {
	user, err := u.userRepository.FindByEmail(email)
	if user != nil || err == nil {
		return fmt.Errorf("user with email %s already exists", email)
	}

	user = NewUser(email, password)
	return u.userRepository.CreateUser(user)
}

func (u *usersService) LoginWithPassword(email, password string) (*User, *UserSession, error) {
	user, err := u.userRepository.FindByEmail(email)
	if err != nil {
		return nil, nil, err
	}

	if user == nil {
		return nil, nil, fmt.Errorf("user with email %s not found", email)
	}

	if !user.ComparePassword(password) {
		return nil, nil, fmt.Errorf("password mismatch")
	}

	session := NewUserSession(user.ID)
	if err := u.userSessionRepository.CreateUserSession(session); err != nil {
		return nil, nil, err
	}

	return user, session, nil
}

func (u *usersService) CurrentUser(sessionID string) (*User, error) {
	session, err := u.userSessionRepository.FindUserSessionByID(sessionID)
	if session == nil || err != nil {
		return nil, fmt.Errorf("session not found")
	}

	user, err := u.userRepository.FindByID(session.UserID)
	if user == nil || err != nil {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

func (u *usersService) CreatePasskeyRegistrationOptions(rpConfig webauthn.RPConfig, userSessionID string, user User) (*webauthn.PublicKeyCredentialCreationOptions, *PasskeySession, error) {
	webauthnUser := user.ToWebAuthnUser(nil)
	options, webauthnSession, err := webauthn.CreateRegistrationCeremonyOptions(rpConfig, *webauthnUser, webauthn.WithAttestationPreference(webauthn.AttestationConveyancePreferenceIndirect))
	if err != nil {
		return nil, nil, err
	}

	passkeySession := NewPasskeySession(userSessionID, webauthnSession)
	if err := u.passkeySessionRepository.CreatePasskeySession(passkeySession); err != nil {
		return nil, nil, err
	}

	return options, passkeySession, nil
}

func (u *usersService) PasskeyRegistration(rpConfig webauthn.RPConfig, user User, userSessionID string, registrationResponse webauthn.RegistrationResponseJSON) error {
	debugRegistrationResponse(registrationResponse)

	session, err := u.passkeySessionRepository.FindByID(userSessionID)
	if err != nil {
		return err
	}

	defer u.passkeySessionRepository.DeleteByID(userSessionID)

	record, err := webauthn.VerifyRegistrationCelemonyResponse(rpConfig, *session.ToWebAuthnSession(), registrationResponse, nil)
	if err != nil {
		return err
	}

	passkey := NewUserPasskey(user.ID, *record)
	if err := u.userPasskeyRepository.SavePaskey(passkey); err != nil {
		return err
	}

	return nil
}

func (u *usersService) CreatePasskeyAuthenticationOptions(rpConfig webauthn.RPConfig) (*webauthn.PublicKeyCredentialRequestOptions, *PasskeySession, error) {
	sessionID := GenerateID()
	options, session, err := webauthn.CreateAuthenticationOptions(rpConfig, []byte(sessionID), webauthn.WithAttestaion(webauthn.AttestationConveyancePreferenceIndirect))
	if err != nil {
		return nil, nil, err
	}

	passkeySession := NewPasskeySession(sessionID, session)
	if err := u.passkeySessionRepository.CreatePasskeySession(passkeySession); err != nil {
		return nil, nil, err
	}

	return options, passkeySession, nil
}

func (u *usersService) LoginWithPasskey(rpConfig webauthn.RPConfig, passkeySessionID string, response webauthn.AuthenticationResponseJSON) (*User, *UserSession, error) {
	debugAuthenticationResponse(response)
	passkeySession, err := u.passkeySessionRepository.FindByID(passkeySessionID)
	if err != nil {
		return nil, nil, err
	}

	defer u.passkeySessionRepository.DeleteByID(passkeySessionID)

	param := webauthn.VerifyDiscoverableCredentialAuthenticationParam{
		RPConfig:           rpConfig,
		Challenge:          passkeySession.Challenge,
		AllowedCredentials: passkeySession.AllowedCredentials,
		UserVerification:   passkeySession.UserVerification,
	}

	webauthnUser, credentialRecord, err := webauthn.VerifyDiscoverableCredentialAuthenticationResponse(
		param,
		u.discoverUserPaskey,
		response,
		nil,
	)

	if err != nil {
		return nil, nil, err
	}

	user := WebAuthnUserToUser(webauthnUser)

	passkey, err := u.userPasskeyRepository.FindPasskeyByID(credentialRecord.ID)
	if err != nil {
		return nil, nil, err
	}

	passkey.Credential = *credentialRecord
	if err := u.userPasskeyRepository.SavePaskey(&passkey); err != nil {
		return nil, nil, err
	}

	session := NewUserSession(user.ID)
	if err := u.userSessionRepository.CreateUserSession(session); err != nil {
		return nil, nil, err
	}

	return user, session, err
}

func (u *usersService) discoverUserPaskey(credentialRawID []byte, userHandle string) (*webauthn.WebAuthnUser, *webauthn.CredentialRecord, error) {
	passkeys, err := u.userPasskeyRepository.FindPasskeysByUserID(userHandle)
	if err != nil {
		return nil, nil, err
	}

	credentials := make([]webauthn.CredentialRecord, len(passkeys))
	for i, passkey := range passkeys {
		credentials[i] = passkey.Credential
	}

	for _, passkey := range passkeys {
		if bytes.Equal(passkey.ID, credentialRawID) {
			user, err := u.userRepository.FindByID(passkey.UserID)
			if err != nil {
				return nil, nil, err
			}

			webAuthnUser := user.ToWebAuthnUser(credentials)
			return webAuthnUser, &passkey.Credential, nil
		}
	}

	return nil, nil, fmt.Errorf("credential not found")
}

func debugRegistrationResponse(response webauthn.RegistrationResponseJSON) {
	r, _ := response.Parse()
	p.P(r)
}

func debugAuthenticationResponse(response webauthn.AuthenticationResponseJSON) {
	r, _ := response.Parse()
	p.P(r)
}

func NewUsersService(
	userRepository UserRepository,
	userSessionRepository UserSessionRepository,
	passkeySessionRepository PasskeySessionRepository,
	userPasskeyRepository UserPasskeyRepository,
) UsersService {
	return &usersService{
		userRepository:           userRepository,
		userSessionRepository:    userSessionRepository,
		passkeySessionRepository: passkeySessionRepository,
		userPasskeyRepository:    userPasskeyRepository,
	}
}
