package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

type COSEKeyType int

// https://www.iana.org/assignments/cose/cose.xhtml#key-type
const (
	COSEKeyTypeReserved COSEKeyType = iota
	COSEKeyTypeOKP
	COSEKeyTypeEC2
	COSEKeyTypeRSA
	COSEKeyTypeSymmetric
	COSEKeyTypeHSS_LMS
	COSEKeyTypeWalnutDSA
)

type PublicKeyData interface {
	Verify(data []byte, signature []byte) (bool, error)
}

// publicKeyData represents a COSE_Key object
// https://datatracker.ietf.org/doc/html/rfc8152#section-13
type publicKeyData struct {
	// https://datatracker.ietf.org/doc/html/rfc8152#section-13
	KeyType   int64 `cbor:"1,keyasint" json:"kty"` // required
	Algorithm int64 `cbor:"3,keyasint" json:"alg"` // required
}

type OKPPublicKeyData struct {
	publicKeyData publicKeyData
}

// EC2PublicKeyData represents an Elliptic Curve public key
// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
// https://datatracker.ietf.org/doc/html/rfc8392#appendix-A.2.3
type EC2PublicKeyData struct {
	publicKeyData

	Curve       int64  `cbor:"-1,keyasint" json:"crv"`
	XCoordinate []byte `cbor:"-2,keyasint" json:"x"`
	YCoordinate []byte `cbor:"-3,keyasint" json:"y"`
}

func (p *OKPPublicKeyData) Verify(data []byte, signature []byte) (bool, error) {
	return false, nil
}

func (p *EC2PublicKeyData) Verify(data []byte, signature []byte) (bool, error) {
	var curve elliptic.Curve
	var hasher crypto.Hash

	// https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
	switch p.Algorithm {
	case int64(AlgES256):
		curve = elliptic.P256()
		hasher = crypto.SHA256
	case int64(AlgES384):
		curve = elliptic.P384()
		hasher = crypto.SHA384
	case int64(AlgES512):
		curve = elliptic.P521()
		hasher = crypto.SHA512
	default:
		return false, fmt.Errorf("unsupported algorithm: %d", p.Algorithm)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(p.XCoordinate),
		Y:     new(big.Int).SetBytes(p.YCoordinate),
	}

	h := hasher.New()
	if _, err := h.Write(data); err != nil {
		return false, err
	}

	return ecdsa.VerifyASN1(pubKey, h.Sum(nil), signature), nil
}
