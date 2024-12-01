# go-webauthn

This library helps implement [WebAuthn](<(https://www.w3.org/TR/webauthn-3)>) Relying Party functionality in Go.

> [!WARNING]
> While it does not fully comply with the WebAuthn Level 3 specification at present, it can implement authentication using Passkeys.

# Examples

See the [example](./example) directory for examples on how to use this library.

### Credential Registration

**Initiation phase**

```go
var (
    rpConfig = &webauthn.RPConfig{
    		ID:      "localhost",
    		Name:    "localhost",
    		Origins: []string{"http://localhost:8080"},
    	}
)

// Save the session and return the options as a response
options, webauthnSession, err := webauthn.CreateRegistrationCeremonyOptions(rpConfig, *webauthnUser)
```

**Verification phase**

```go
var registrationResponse webauthn.RegistrationResponseJSON
if err := json.NewDecoder(r.Body).Decode(&registrationResponse); err != nil {
    http.Error(w, err.Error(), http.StatusBadRequest)
	return
}

// Save the credential associated with the user.
// See WebAuthn Level 3 for data that RP should save: https://www.w3.org/TR/webauthn-3/#reg-ceremony-store-credential-record
// Also, it should be verified that credential.ID is not associated with other users.
credential, err := webauthn.VerifyRegistrationCelemonyResponse(rpConfig, *session, registrationResponse, nil)
```

### Authentication

**Initiation phase**

```go
// Save the session and return the options as a response
options, session, err := webauthn.CreateAuthenticationOptions(rpConfig, sessionID)
```

**Verification phase**

```go
var authenticationResponse webauthn.AuthenticationResponseJSON
if err := json.NewDecoder(r.Body).Decode(&authenticationResponse); err != nil {
	http.Error(w, err.Error(), http.StatusBadRequest)
	return
}

param := webauthn.VerifyDiscoverableCredentialAuthenticationParam{
	RPConfig:           rpConfig,
	Challenge:          session.Challenge,
	AllowedCredentials: session.AllowedCredentials,
	UserVerification:   session.UserVerification,
}

webauthnUser, credentialRecord, err := webauthn.VerifyDiscoverableCredentialAuthenticationResponse(
	param,
	discoverUserPasskey,
	authenticationResponse,
	nil,
)

user := ToYourUserModel(webauthnUser)
user.UpdatePasskey(credentialRecord)

// en: discoverUserPasskey is a function that RP should implement to get the passkey associated with the user from your database using credentialRawID and userHandle as keys.
func discoverUserPasskey(credentialRawID []byte, userHandle string) (*webauthn.WebAuthnUser, *webauthn.CredentialRecord, error) {}
```

## Modify registration and authentication options

You can modify registration and authentication options using `webauthn.WithUserVerification` and `webauthn.WithAttestaion`.

```go
webauthn.CreateRegistrationCeremonyOptions(
    rpConfig,
    *webauthnUser,
    webauthn.WithAttestationPreference(webauthn.AttestationConveyancePreferenceIndirect)
)
```

# Status

This library's releases are not stable. Therefore, breaking changes may be made without warning.

## Support Attestation Statement Format

| Attestation Statement Format | Supported |
| ---------------------------- | --------- |
| none                         | Yes       |
| packed                       | Yes       |
| apple                        | No        |
| android-key                  | No        |
| android-safetynet            | No        |
| tpm                          | No        |
| fido-u2f                     | No        |

## Client Extensions

Client Extensions are not yet supported.
