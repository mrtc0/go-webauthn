package webauthn

import (
	"crypto/subtle"
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

func SecureCompare(given string, actual string) bool {
	return subtle.ConstantTimeCompare([]byte(given), []byte(actual)) == 1
}

func SecureCompareByte(given []byte, actual []byte) bool {
	return subtle.ConstantTimeCompare(given, actual) == 1
}
