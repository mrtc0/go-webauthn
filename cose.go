package webauthn

import "crypto/x509"

// https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier
type COSEAlgorithmIdentifier int

// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
const (
	// AlgHSS_LMS is HSS/LMS hash-based digital signature
	AlgHSS_LMS COSEAlgorithmIdentifier = -46
	// AlgSHAKE256 is SHAKE-256 512-bit Hash Value
	AlgSHAKE256 COSEAlgorithmIdentifier = -45
	// AlgSHA512 is SHA-2 512-bit Hash
	AlgSHA512 COSEAlgorithmIdentifier = -44
	// AlgSHA384 is SHA-2 384-bit Hash
	AlgSHA384 COSEAlgorithmIdentifier = -43
	// AlgRSAESOAEP_SHA512 is RSAES-OAEP w/ SHA-512
	AlgRSAESOAEP_SHA512 COSEAlgorithmIdentifier = -42
	// AlgRSAESOAEP_SHA256 is RSAES-OAEP w/ SHA-256
	AlgRSAESOAEP_SHA256 COSEAlgorithmIdentifier = -41
	// AlgRSAESOAEP_RFC8017_Default_Parameters is RSAES-OAEP w/ SHA-1
	AlgRSAESOAEP_RFC8017_Default_Parameters COSEAlgorithmIdentifier = -40
	// AlgPS512 is RSASSA-PSS w/ SHA-512
	AlgPS512 COSEAlgorithmIdentifier = -39
	// AlgPS384 is RSASSA-PSS w/ SHA-384
	AlgPS384 COSEAlgorithmIdentifier = -38
	// AlgPS256 is RSASSA-PSS w/ SHA-256
	AlgPS256 COSEAlgorithmIdentifier = -37
	// AlgES512 is ECDSA w/ SHA-512
	AlgES512 COSEAlgorithmIdentifier = -36
	// AlgES384 is ECDSA w/ SHA-384
	AlgES384 COSEAlgorithmIdentifier = -35
	// AlgECDH_SS_A256KW is ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key
	AlgECDH_SS_A256KW COSEAlgorithmIdentifier = -34
	// AlgECDH_SS_A192KW is ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key
	AlgECDH_SS_A192KW COSEAlgorithmIdentifier = -33
	// AlgECDH_SS_A128KW is ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key
	AlgECDH_SS_A128KW COSEAlgorithmIdentifier = -32
	// AlgECDH_ES_A256KW is ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key
	AlgECDH_ES_A256KW COSEAlgorithmIdentifier = -31
	// AlgECDH_ES_A192KW is ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key
	AlgECDH_ES_A192KW COSEAlgorithmIdentifier = -30
	// AlgECDH_ES_A128KW is ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key
	AlgECDH_ES_A128KW COSEAlgorithmIdentifier = -29
	// AlgECDH_SS_HKDF_512 is ECDH SS w/ HKDF - generate key directly
	AlgECDH_SS_HKDF_512 COSEAlgorithmIdentifier = -28
	// AlgECDH_SS_HKDF_256 is ECDH SS w/ HKDF - generate key directly
	AlgECDH_SS_HKDF_256 COSEAlgorithmIdentifier = -27
	// AlgECDH_ES_HKDF_512 is ECDH ES w/ HKDF - generate key directly
	AlgECDH_ES_HKDF_512 COSEAlgorithmIdentifier = -26
	// AlgECDH_ES_HKDF_256 is ECDH ES w/ HKDF - generate key directly
	AlgECDH_ES_HKDF_256 COSEAlgorithmIdentifier = -25
	// AlgSHAKE128 is SHAKE-128 256-bit Hash Value
	AlgSHAKE128 COSEAlgorithmIdentifier = -18
	// AlgSHA_512_256 is SHA-2 512-bit Hash truncated to 256-bits
	AlgSHA_512_256 COSEAlgorithmIdentifier = -17
	// AlgSHA_256 is SHA-2 256-bit Hash
	AlgSHA_256 COSEAlgorithmIdentifier = -16
	// Algdirect_HKDF_AES_256 is Shared secret w/ AES-MAC 256-bit key
	Algdirect_HKDF_AES_256 COSEAlgorithmIdentifier = -13
	// Algdirect_HKDF_AES_128 is Shared secret w/ AES-MAC 128-bit key
	Algdirect_HKDF_AES_128 COSEAlgorithmIdentifier = -12
	// Algdirect_HKDF_SHA_512 is Shared secret w/ HKDF and SHA-512
	Algdirect_HKDF_SHA_512 COSEAlgorithmIdentifier = -11
	// Algdirect_HKDF_SHA_256 is Shared secret w/ HKDF and SHA-256
	Algdirect_HKDF_SHA_256 COSEAlgorithmIdentifier = -10
	// AlgEdDSA is EdDSA
	AlgEdDSA COSEAlgorithmIdentifier = -8
	// AlgES256 is ECDSA w/ SHA-256
	AlgES256 COSEAlgorithmIdentifier = -7
	// Algdirect is Direct use of CEK
	Algdirect COSEAlgorithmIdentifier = -6
	// AlgA256KW is AES Key Wrap w/ 256-bit key
	AlgA256KW COSEAlgorithmIdentifier = -5
	// AlgA192KW is AES Key Wrap w/ 192-bit key
	AlgA192KW COSEAlgorithmIdentifier = -4
	// AlgA128KW is AES Key Wrap w/ 128-bit key
	AlgA128KW COSEAlgorithmIdentifier = -3
	// AlgA128GCM is AES-GCM mode w/ 128-bit key, 128-bit tag
	AlgA128GCM COSEAlgorithmIdentifier = 1
	// AlgA192GCM is AES-GCM mode w/ 192-bit key, 128-bit tag
	AlgA192GCM COSEAlgorithmIdentifier = 2
	// AlgA256GCM is AES-GCM mode w/ 256-bit key, 128-bit tag
	AlgA256GCM COSEAlgorithmIdentifier = 3
	// AlgHMAC_256_64 is HMAC w/ SHA-256 truncated to 64 bits
	AlgHMAC_256_64 COSEAlgorithmIdentifier = 4
	// AlgHMAC_256_256 is HMAC w/ SHA-256
	AlgHMAC_256_256 COSEAlgorithmIdentifier = 5
	// AlgHMAC_384_384 is HMAC w/ SHA-384
	AlgHMAC_384_384 COSEAlgorithmIdentifier = 6
	// AlgHMAC_512_512 is HMAC w/ SHA-512
	AlgHMAC_512_512 COSEAlgorithmIdentifier = 7
	// AlgAES_CCM_16_64_128 is AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce
	AlgAES_CCM_16_64_128 COSEAlgorithmIdentifier = 10
	// AlgAES_CCM_16_64_256 is AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce
	AlgAES_CCM_16_64_256 COSEAlgorithmIdentifier = 11
	// AlgAES_CCM_64_64_128 is AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
	AlgAES_CCM_64_64_128 COSEAlgorithmIdentifier = 12
	// AlgAES_CCM_64_64_256 is AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce
	AlgAES_CCM_64_64_256 COSEAlgorithmIdentifier = 13
	// AlgAES_MAC_128_64 is AES-MAC 128-bit key, 64-bit tag
	AlgAES_MAC_128_64 COSEAlgorithmIdentifier = 14
	// AlgAES_MAC_256_64 is AES-MAC 256-bit key, 64-bit tag
	AlgAES_MAC_256_64 COSEAlgorithmIdentifier = 15
	// AlgChaCha20_Poly1305 is ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag
	AlgChaCha20_Poly1305 COSEAlgorithmIdentifier = 24
	// AlgAES_MAC_128_128 is AES-MAC 128-bit key, 128-bit tag
	AlgAES_MAC_128_128 COSEAlgorithmIdentifier = 25
	// AlgAES_MAC_256_128 is AES-MAC 256-bit key, 128-bit tag
	AlgAES_MAC_256_128 COSEAlgorithmIdentifier = 26
	// AlgAES_CCM_16_128_128 is AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce
	AlgAES_CCM_16_128_128 COSEAlgorithmIdentifier = 30
	// AlgAES_CCM_16_128_256 is AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce
	AlgAES_CCM_16_128_256 COSEAlgorithmIdentifier = 31
	// AlgAES_CCM_64_128_128 is AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce
	AlgAES_CCM_64_128_128 COSEAlgorithmIdentifier = 32
	// AlgAES_CCM_64_128_256 is AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce
	AlgAES_CCM_64_128_256 COSEAlgorithmIdentifier = 33
)

func defaultCredentialParameters() []PublicKeyCredentialParameters {
	defaultAlgs := []COSEAlgorithmIdentifier{
		AlgHSS_LMS,
		AlgSHAKE256,
		AlgSHA512,
		AlgSHA384,
		AlgRSAESOAEP_SHA512,
		AlgRSAESOAEP_SHA256,
		AlgRSAESOAEP_RFC8017_Default_Parameters,
		AlgPS512,
		AlgPS384,
		AlgPS256,
		AlgES512,
		AlgES384,
		AlgECDH_SS_A256KW,
		AlgECDH_SS_A192KW,
		AlgECDH_SS_A128KW,
		AlgECDH_ES_A256KW,
		AlgECDH_ES_A192KW,
		AlgECDH_ES_A128KW,
		AlgECDH_SS_HKDF_512,
		AlgECDH_SS_HKDF_256,
		AlgECDH_ES_HKDF_512,
		AlgECDH_ES_HKDF_256,
		AlgSHAKE128,
		AlgSHA_512_256,
		AlgSHA_256,
		Algdirect_HKDF_AES_256,
		Algdirect_HKDF_AES_128,
		Algdirect_HKDF_SHA_512,
		Algdirect_HKDF_SHA_256,
		AlgEdDSA,
		AlgES256,
		Algdirect,
		AlgA256KW,
		AlgA192KW,
		AlgA128KW,
		AlgA128GCM,
		AlgA192GCM,
		AlgA256GCM,
		AlgHMAC_256_64,
		AlgHMAC_256_256,
		AlgHMAC_384_384,
		AlgHMAC_512_512,
		AlgAES_CCM_16_64_128,
		AlgAES_CCM_16_64_256,
		AlgAES_CCM_64_64_128,
		AlgAES_CCM_64_64_256,
		AlgAES_MAC_128_64,
		AlgAES_MAC_256_64,
		AlgChaCha20_Poly1305,
		AlgAES_MAC_128_128,
		AlgAES_MAC_256_128,
		AlgAES_CCM_16_128_128,
		AlgAES_CCM_16_128_256,
		AlgAES_CCM_64_128_128,
		AlgAES_CCM_64_128_256,
	}

	defaultPublicKeyCredentialParameters := []PublicKeyCredentialParameters{}

	for _, alg := range defaultAlgs {
		defaultPublicKeyCredentialParameters = append(defaultPublicKeyCredentialParameters, PublicKeyCredentialParameters{
			Type: PublicKeyCredentialTypePublicKey,
			Alg:  alg,
		})
	}

	return defaultPublicKeyCredentialParameters
}

func SignatureAlgorithm(coseAlg COSEAlgorithmIdentifier) x509.SignatureAlgorithm {
	switch coseAlg {
	case AlgES256:
		return x509.ECDSAWithSHA256
	case AlgES384:
		return x509.ECDSAWithSHA384
	case AlgES512:
		return x509.ECDSAWithSHA512
	case AlgPS256:
		return x509.SHA256WithRSAPSS
	case AlgPS384:
		return x509.SHA384WithRSAPSS
	case AlgPS512:
		return x509.SHA512WithRSAPSS
	case AlgEdDSA:
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}
}
