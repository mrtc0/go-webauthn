package webauthn

import "crypto/rand"

const defaultChallengeLength = 16

func GenerateChallenge() (challenge []byte, err error) {
	challenge = make([]byte, defaultChallengeLength)

	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}

	return challenge, nil
}

func IsValidChallenge(challenge []byte) bool {
	return len(challenge) >= defaultChallengeLength
}
