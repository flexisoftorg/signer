// Package signer provides cookie signing and unsigning functionality
// compatible with @fastify/cookie (https://github.com/fastify/fastify-cookie)
//
// Inspired by node-cookie-signature (https://github.com/tj/node-cookie-signature)
package signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
)

// Signer handles signing and unsigning of cookie values
type Signer struct {
	secrets    []string
	signingKey string
}

// UnsignResult contains the result of an unsign operation
type UnsignResult struct {
	Valid bool
	Renew bool   // true if the value was signed with a non-primary secret (for key rotation)
	Value string // the unsigned value, empty if invalid
}

// New creates a new Signer with the given secrets
// The first secret is used for signing, all secrets are used for unsigning (key rotation support)
func New(secrets ...string) *Signer {
	if len(secrets) == 0 {
		panic("at least one secret is required")
	}
	return &Signer{
		secrets:    secrets,
		signingKey: secrets[0],
	}
}

// Sign signs a value and returns the signed string in format: value.signature
func (s *Signer) Sign(value string) string {
	return sign(value, s.signingKey)
}

// Unsign verifies and extracts the value from a signed string
func (s *Signer) Unsign(signedValue string) UnsignResult {
	return unsign(signedValue, s.secrets)
}

// sign creates a signed value using HMAC-SHA256
func sign(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	// Use RawStdEncoding (no padding) to match fastify-cookie
	signature := base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
	return value + "." + signature
}

// unsign verifies and extracts the value from a signed string
func unsign(signedValue string, secrets []string) UnsignResult {
	lastDot := strings.LastIndex(signedValue, ".")
	if lastDot == -1 {
		return UnsignResult{Valid: false, Renew: false, Value: ""}
	}

	value := signedValue[:lastDot]
	actualSig := signedValue[lastDot+1:]

	// URL-decode the signature (browsers may encode special chars like /)
	actualSigDecoded, err := url.PathUnescape(actualSig)
	if err != nil {
		return UnsignResult{Valid: false, Renew: false, Value: ""}
	}

	for i, secret := range secrets {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(value))
		// Use RawStdEncoding (no padding) to match fastify-cookie
		expectedSig := base64.RawStdEncoding.EncodeToString(mac.Sum(nil))

		// Use constant-time comparison to prevent timing attacks
		if len(expectedSig) == len(actualSigDecoded) &&
			hmac.Equal([]byte(expectedSig), []byte(actualSigDecoded)) {
			return UnsignResult{
				Valid: true,
				Renew: i != 0, // renew if not signed with primary secret
				Value: value,
			}
		}
	}

	return UnsignResult{Valid: false, Renew: false, Value: ""}
}

// Sign is a convenience function for one-off signing
func Sign(value, secret string) string {
	return sign(value, secret)
}

// Unsign is a convenience function for one-off unsigning
func Unsign(signedValue, secret string) UnsignResult {
	return unsign(signedValue, []string{secret})
}
