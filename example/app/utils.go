package main

import "github.com/google/uuid"

func GenerateID() string {
	uuid, err := uuid.NewUUID()
	if err != nil {
		panic(err)
	}

	return uuid.String()
}
