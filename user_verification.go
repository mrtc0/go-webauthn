package webauthn

type UserVerification string

const (
	UserVerificationRequired    UserVerification = "required"
	UserVerificationPreferred   UserVerification = "preferred"
	UserVerificationDiscouraged UserVerification = "discouraged"
)

func (uv UserVerification) String() string {
	return string(uv)
}

func (uv UserVerification) IsValid() bool {
	switch uv {
	case UserVerificationRequired, UserVerificationPreferred, UserVerificationDiscouraged:
		return true
	default:
		return false
	}
}

func (uv UserVerification) IsRequired() bool {
	return uv == UserVerificationRequired
}

func (uv UserVerification) IsPreferred() bool {
	return uv == UserVerificationPreferred
}

func (uv UserVerification) IsDiscouraged() bool {
	return uv == UserVerificationDiscouraged
}
