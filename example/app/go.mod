module github.com/mrtc0/go-webauthn/example/simple

go 1.22.5

replace github.com/mrtc0/go-webauthn => ../..

require (
	github.com/asdine/storm/v3 v3.2.1
	github.com/google/uuid v1.6.0
	github.com/mrtc0/go-webauthn v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.29.0
)

require (
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.etcd.io/bbolt v1.3.11 // indirect
	golang.org/x/sys v0.27.0 // indirect
)