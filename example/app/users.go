package main

import (
	"github.com/mrtc0/go-webauthn"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID             string
	Email          string
	HashedPassword string
}

type UserPasskey struct {
	ID         []byte
	UserID     string
	Credential webauthn.CredentialRecord
}

type UserRepository interface {
	CreateUser(user *User) error
	FindByEmail(email string) (*User, error)
	FindByID(id string) (*User, error)
}

type UserPasskeyRepository interface {
	SavePaskey(userPasskey *UserPasskey) error
	FindPasskeysByUserID(userID string) ([]UserPasskey, error)
	FindPasskeyByID(id []byte) (UserPasskey, error)
}

func NewUser(email, password string) *User {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	return &User{
		ID:             GenerateID(),
		Email:          email,
		HashedPassword: string(h),
	}
}

func NewUserPasskey(userID string, credential webauthn.CredentialRecord) *UserPasskey {
	return &UserPasskey{
		ID:         credential.ID,
		UserID:     userID,
		Credential: credential,
	}
}

func WebAuthnUserToUser(wu *webauthn.WebAuthnUser) *User {
	return &User{
		ID:    string(wu.ID),
		Email: wu.Name,
	}
}

func (u *User) ToWebAuthnUser(credentials []webauthn.CredentialRecord) *webauthn.WebAuthnUser {
	return &webauthn.WebAuthnUser{
		ID:          []byte(u.ID),
		Name:        u.Email,
		DisplayName: u.Email,
		Credentials: credentials,
	}
}

func (u *User) ComparePassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.HashedPassword), []byte(password))
	return err == nil
}
