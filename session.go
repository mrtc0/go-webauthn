package webauthn

type Session struct {
	Challenge        string
	RPID             string
	UserID           []byte
	UserVerification string

	AllowedCredentials []PublicKeyCredentialDescriptor
}
