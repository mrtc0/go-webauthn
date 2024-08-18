package webauthn

import (
	"encoding/base64"
)

type Base64URLEncodedByte []byte

func (b Base64URLEncodedByte) Decode() ([]byte, error) {
	out := make([]byte, base64.RawURLEncoding.DecodedLen(len(b)))

	n, err := base64.RawURLEncoding.Decode(out, b)
	if err != nil {
		return nil, err
	}

	return out[:n], nil
}

func (b Base64URLEncodedByte) String() string {
	return base64.RawURLEncoding.EncodeToString(b)
}
