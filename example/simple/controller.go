package main

import (
	"encoding/json"
	"net/http"

	"github.com/mrtc0/go-webauthn"
)

type usersController struct {
	passkeyRelyingPartyConfig webauthn.RPConfig
	usersService              UsersService
}

func NewUsersController(
	rpConfig webauthn.RPConfig,
	usersService UsersService,
) *usersController {
	return &usersController{
		passkeyRelyingPartyConfig: rpConfig,
		usersService:              usersService,
	}
}

func (u *usersController) CurrentUser(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := u.usersService.CurrentUser(sessionID.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	type response struct {
		Email string `json:"email"`
	}

	data, err := json.Marshal(&response{Email: user.Email})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (u *usersController) Signup(w http.ResponseWriter, r *http.Request) {
	type registrationRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := u.usersService.Signup(req.Email, req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (u *usersController) LoginWithPassword(w http.ResponseWriter, r *http.Request) {
	type loginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, session, err := u.usersService.LoginWithPassword(req.Email, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: session.ID,
		Path:  "/",
	})
	w.WriteHeader(http.StatusOK)
}

func (u *usersController) PasskeyRegistrationStart(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := u.usersService.CurrentUser(sessionID.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	options, _, err := u.usersService.CreatePasskeyRegistrationOptions(u.passkeyRelyingPartyConfig, sessionID.Value, *user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json, err := json.Marshal(options)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func (u *usersController) PasskeyRegistrationFinish(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := u.usersService.CurrentUser(sessionID.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var registrationResponse webauthn.RegistrationResponseJSON
	if err := json.NewDecoder(r.Body).Decode(&registrationResponse); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := u.usersService.PasskeyRegistration(u.passkeyRelyingPartyConfig, *user, sessionID.Value, registrationResponse); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type response struct {
		Verified bool `json:"verified"`
	}
	data, err := json.Marshal(&response{Verified: true})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (u *usersController) LoginWithPasskeyStart(w http.ResponseWriter, r *http.Request) {
	options, session, err := u.usersService.CreatePasskeyAuthenticationOptions(u.passkeyRelyingPartyConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json, err := json.Marshal(options)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: session.ID,
		Path:  "/",
	})

	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func (u *usersController) LoginWithPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var response webauthn.AuthenticationResponseJSON
	if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, userSession, err := u.usersService.LoginWithPasskey(u.passkeyRelyingPartyConfig, sessionID.Value, response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: userSession.ID,
		Path:  "/",
	})
	w.WriteHeader(http.StatusOK)
}
