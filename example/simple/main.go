package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/mrtc0/go-webauthn"
)

var webauthnUser = webauthn.WebAuthnUser{
	ID:          []byte("12345"),
	Name:        "mrtc0",
	DisplayName: "Kohei Morita",
}

var rp = webauthn.RP{
	ID:     "localhost",
	Name:   "localhost",
	Origin: "http://localhost:8080",
}

var sessionStore = make(map[string]*webauthn.Session)

func main() {
	server := http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/":
				http.ServeFile(w, r, "index.html")
			case "/webauthn/registration/start":
				registrationStart(w, r)
			case "/webauthn/registration/finish":
				registrationFinish(w, r)
			default:
				http.NotFound(w, r)
			}
		}),
	}

	server.ListenAndServe()
}

func registrationStart(w http.ResponseWriter, r *http.Request) {
	authenticatorSelection := webauthn.AuthenticatorSelectionCriteria{
		// ref. https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
		UserVerification:   "preferred",
		ResidentKey:        "required",
		RequireResidentKey: true,
	}
	options, session, err := webauthn.CreateOptionsForRegistrationCeremony(&webauthnUser, &rp, webauthn.WithAuthenticatorSelection(authenticatorSelection))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionStore[string(webauthnUser.ID)] = session

	w.Header().Set("Content-Type", "application/json")
	json, _ := json.Marshal(options)
	w.Write(json)
}

func registrationFinish(w http.ResponseWriter, r *http.Request) {
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

	record, err := webauthn.CreateCredential(&webauthnUser, sessionStore[string(webauthnUser.ID)], &response, &rp)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Credential: %#v\n", record)
	w.Write([]byte("{verified: true}"))
}
