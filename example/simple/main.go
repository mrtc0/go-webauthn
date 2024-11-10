package main

import (
	"net/http"

	"github.com/mrtc0/go-webauthn"
)

func main() {
	rpConfig := &webauthn.RPConfig{
		ID:      "localhost",
		Name:    "localhost",
		Origins: []string{"http://localhost:8080"},
	}

	con := NewControllers(rpConfig)

	server := http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/":
				http.ServeFile(w, r, "index.html")
			case "/api/signup":
				con.usersController.Signup(w, r)
			case "/api/login":
				con.usersController.LoginWithPassword(w, r)
			case "/api/user/passkey/registration/start":
				con.usersController.PasskeyRegistrationStart(w, r)
			case "/api/user/passkey/registration":
				con.usersController.PasskeyRegistrationFinish(w, r)
			case "/api/login/passkey/start":
				con.usersController.LoginWithPasskeyStart(w, r)
			case "/api/login/passkey":
				con.usersController.LoginWithPasskeyFinish(w, r)
			case "/api/user":
				con.usersController.CurrentUser(w, r)
			default:
				http.NotFound(w, r)
			}
		}),
	}

	server.ListenAndServe()
}

type Controllers struct {
	usersController *usersController
}

func NewControllers(rpConfig *webauthn.RPConfig) *Controllers {
	db := NewstormDatabase()

	// Initialize repositories
	userRepository := NewUserRepository(*db)
	userSessionRepository := NewUsersSessionRepository(*db)
	passkeySessionRepository := NewPasskeySessionRepository(*db)
	userPasskeyRepostioty := NewUserPasskeyRepository(*db)

	// initialize services
	usersService := NewUsersService(userRepository, userSessionRepository, passkeySessionRepository, userPasskeyRepostioty)

	return &Controllers{
		usersController: NewUsersController(*rpConfig, usersService),
	}
}
