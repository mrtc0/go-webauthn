package main

import (
	storm "github.com/asdine/storm/v3"
)

var (
	userBucket           = "users"
	userSessionBucket    = "user_sessions"
	passkeySessionBucket = "passkey_sessions"
	userPasskeyBucket    = "user_passkeys"
)

type stormDatabase struct {
	*storm.DB
}

func NewstormDatabase() *stormDatabase {
	db, err := storm.Open("webauthn-example.db")
	if err != nil {
		panic(err)
	}

	return &stormDatabase{db}
}

type userRepositoryImpl struct {
	storm.Node
}

type userSessionRepositoryImpl struct {
	storm.Node
}

type passkeySessionRepositoryImpl struct {
	storm.Node
}

type userPasskeyRepositoryImpl struct {
	storm.Node
}

func (u *userRepositoryImpl) CreateUser(user *User) error {
	return u.Save(user)
}

func (u *userRepositoryImpl) FindByEmail(email string) (*User, error) {
	var user User
	if err := u.One("Email", email, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (u *userRepositoryImpl) FindByID(id string) (*User, error) {
	var user User
	if err := u.One("ID", id, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func (u *userPasskeyRepositoryImpl) SavePaskey(userPasskey *UserPasskey) error {
	return u.Save(userPasskey)
}

func (u *userPasskeyRepositoryImpl) FindUserPasskeys(userID string) ([]UserPasskey, error) {
	var userPasskeys []UserPasskey
	if err := u.Find("UserID", userID, &userPasskeys); err != nil {
		return nil, err
	}
	return userPasskeys, nil
}

func (u *userSessionRepositoryImpl) CreateUserSession(session *UserSession) error {
	return u.Save(session)
}

func (u *userSessionRepositoryImpl) FindUserSessionByID(id string) (*UserSession, error) {
	var session UserSession
	if err := u.One("ID", id, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (p *passkeySessionRepositoryImpl) CreatePasskeySession(session *PasskeySession) error {
	return p.Save(session)
}

func (p *passkeySessionRepositoryImpl) FindByID(ID string) (*PasskeySession, error) {
	var passkeySession PasskeySession
	if err := p.One("ID", ID, &passkeySession); err != nil {
		return nil, err
	}
	return &passkeySession, nil
}

func (p *passkeySessionRepositoryImpl) DeleteByID(ID string) error {
	return p.DeleteStruct(&PasskeySession{ID: ID})
}

func NewUserRepository(db stormDatabase) UserRepository {
	return &userRepositoryImpl{db.From(userBucket)}
}

func NewUsersSessionRepository(db stormDatabase) UserSessionRepository {
	return &userSessionRepositoryImpl{db.From(userSessionBucket)}
}

func NewPasskeySessionRepository(db stormDatabase) PasskeySessionRepository {
	return &passkeySessionRepositoryImpl{db.From(passkeySessionBucket)}
}

func NewUserPasskeyRepository(db stormDatabase) UserPasskeyRepository {
	return &userPasskeyRepositoryImpl{db.From(userPasskeyBucket)}
}
