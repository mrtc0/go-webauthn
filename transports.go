package webauthn

type AuthenticatorTransport string

const (
	AuthenticatorTransportUSB      AuthenticatorTransport = "usb"
	AuthenticatorTransportNFC      AuthenticatorTransport = "nfc"
	AuthenticatorTransportBLE      AuthenticatorTransport = "ble"
	AuthenticatorTransportHybrid   AuthenticatorTransport = "hybrid"
	AuthenticatorTransportInternal AuthenticatorTransport = "internal"
)
