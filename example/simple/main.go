package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/mrtc0/go-webauthn"
)

var webauthnUser = &webauthn.WebAuthnUser{
	ID:          []byte("12345"),
	Name:        "mrtc0",
	DisplayName: "Kohei Morita",
}

var sessionStore = make(map[string]*webauthn.Session)

func main() {
	rpConfig := &webauthn.RPConfig{
		ID:     "localhost",
		Name:   "localhost",
		Origin: "http://localhost:8080",
	}

	rp := webauthn.NewRelyingParty(rpConfig)
	h := RPHandler{rp: *rp}

	server := http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/":
				http.ServeFile(w, r, "index.html")
			case "/webauthn/registration/start":
				h.registrationStart(w, r)
			case "/webauthn/registration/finish":
				h.registrationFinish(w, r)
			case "/webauthn/login/start":
				h.loginStart(w, r)
			case "/webauthn/login/finish":
				h.loginFinish(w, r)
			default:
				http.NotFound(w, r)
			}
		}),
	}

	server.ListenAndServe()
}

type RPHandler struct {
	rp webauthn.RelyingParty
}

func (h RPHandler) registrationStart(w http.ResponseWriter, r *http.Request) {
	authenticatorSelection := webauthn.AuthenticatorSelectionCriteria{
		// ref. https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
		UserVerification:   "preferred",
		ResidentKey:        "required",
		RequireResidentKey: true,
	}
	options, session, err := h.rp.CreateOptionsForRegistrationCeremony(webauthnUser, webauthn.WithAuthenticatorSelection(authenticatorSelection))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionStore[string(webauthnUser.ID)] = session

	w.Header().Set("Content-Type", "application/json")
	json, _ := json.Marshal(options)
	w.Write(json)
}

func (h RPHandler) registrationFinish(w http.ResponseWriter, r *http.Request) {
	length, err := strconv.Atoi(r.Header.Get("Content-Length"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	body := make([]byte, length)
	length, err = r.Body.Read(body)
	if err != nil && err != io.EOF {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	/*
		var response webauthn.AuthenticatorAttestationResponse
		if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	*/

	fmt.Printf("Body: %s\n", body[:length])
	var response webauthn.RegistrationResponseJSON
	if err := json.Unmarshal(body[:length], &response); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	record, err := h.rp.CreateCredential(webauthnUser, sessionStore[string(webauthnUser.ID)], &response)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	webauthnUser.Credentials = append(webauthnUser.Credentials, *record)
	fmt.Printf("Registration success, userID: %s, credentialID: %s\n", webauthnUser.ID, []byte(record.ID))
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{verified: true}"))
}

func (h RPHandler) loginStart(w http.ResponseWriter, r *http.Request) {
	sessionID := generateSessionID(32)
	options, session, err := h.rp.CreateOptionsForAuthenticationCeremony([]byte(sessionID))

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionStore[sessionID] = session

	w.Header().Set("Content-Type", "application/json")
	json, _ := json.Marshal(options)
	http.SetCookie(w, &http.Cookie{
		Name:  "sessionID",
		Value: sessionID,
		Path:  "/",
	})
	w.Write(json)
}

func (h RPHandler) loginFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("sessionID")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sessionID := cookie.Value

	var response webauthn.AuthenticationResponseJSON
	if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Printf("request body:\n\t%#v\n", response)

	webauthnUser, credential, err := h.rp.Authentication(func(credentialRawID []byte, userHandle string) (*webauthn.WebAuthnUser, *webauthn.CredentialRecord, error) {
		return webauthnUser, &webauthnUser.Credentials[0], nil
	}, sessionStore[sessionID], &response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("logged in: %s, %#v\n", webauthnUser.ID, credential)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{verified: true}"))
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func generateSessionID(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
