package webauthn

import "crypto/rand"

const defaultChallengeLength = 16

func GenerateChallenge() (challenge Base64URLEncodedByte, err error) {
	challenge = make([]byte, defaultChallengeLength)

	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}

	return challenge, nil
}
