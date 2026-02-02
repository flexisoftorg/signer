package signer

import (
	"net/url"
	"strings"
	"testing"
)

func TestSignAndUnsign(t *testing.T) {
	secret := "notasecret"
	value := "cookie-value"

	signer := New(secret)
	signed := signer.Sign(value)

	result := signer.Unsign(signed)
	if !result.Valid {
		t.Errorf("Unsign failed: got invalid for signed value %q", signed)
	}

	if result.Value != value {
		t.Errorf("Unsign returned wrong value: got %q, want %q", result.Value, value)
	}
}
func TestSignAndUnsignWithHyphens(t *testing.T) {
	secret := "not-a-secret"
	value := "cookie-value"

	signer := New(secret)
	signed := signer.Sign(value)

	result := signer.Unsign(signed)
	if !result.Valid {
		t.Errorf("Unsign failed: got invalid for signed value %q", signed)
	}

	if result.Value != value {
		t.Errorf("Unsign returned wrong value: got %q, want %q", result.Value, value)
	}
}

func TestUnsign(t *testing.T) {
	secret := "not-a-secret"
	value := "bc21cfb06cfb5a54b852e6b883a548c7ad3921bafb378c21"
	signed := "bc21cfb06cfb5a54b852e6b883a548c7ad3921bafb378c21.7WZsZEMeoHmdXydjelMKc%2BtAkHA03lyyBkNBYZIfX8s"
	signer := New(secret)
	result := signer.Unsign(signed)
	if !result.Valid {
		t.Errorf("Unsign failed: got invalid for signed value %q", signed)
	}
	if result.Value != value {
		t.Errorf("Unsign returned wrong value: got %q, want %q", result.Value, value)
	}
}
func TestUnsign2(t *testing.T) {
	secret := "not-a-secret"
	signed := "fa7bbacd695d549e23b84ab1755fb5edcc19b56b2e4c9195.fW2Yk33ZHbX+2nwe7ohRK48q+7Ckbd3IIbhbheKU6lA"

	signer := New(secret)

	urlDecodedValue, err := url.QueryUnescape(signed)
	if err != nil {
		t.Fatalf("Failed to URL-decode signed value: %v", err)
	}

	result2 := signer.Unsign(urlDecodedValue)
	if result2.Valid {
		t.Errorf("Unsign succeeded: got valid for URL-decoded signed value %q", urlDecodedValue)
	}

	result := signer.Unsign(signed)
	if !result.Valid {
		t.Errorf("Unsign failed: got invalid for signed value %q", signed)
	}

}

func TestSignAndUnsign_WeirdValues(t *testing.T) {
	secret := "supersecretkey"
	signer := New(secret)

	values := []string{
		"",                              // empty string
		" ",                             // space
		"value.with.dot",                // dot in value
		"value/with/slash",              // slash
		"value?with=query&params",       // query params
		"value%with%percent",            // percent
		"value;with:semicolon",          // semicolon
		"value=with=equals",             // equals
		"value\nwith\nnewline",          // newline
		string([]byte{0, 1, 2, 3, 255}), // non-printable bytes
	}

	for _, v := range values {
		signed := signer.Sign(v)
		result := signer.Unsign(signed)
		if !result.Valid || result.Value != v {
			t.Errorf("Unsign failed for value %q: got valid=%v, value=%q", v, result.Valid, result.Value)
		}
	}
}

func TestSignAndUnsign_Tampered(t *testing.T) {
	secret := "supersecretkey"
	signer := New(secret)

	value := "cookie-value"
	signed := signer.Sign(value)

	// Tamper with value
	tampered := "evil-value" + signed[strings.Index(signed, "."):] // keep signature, change value
	result := signer.Unsign(tampered)
	if result.Valid {
		t.Errorf("Unsign should fail for tampered value, got valid")
	}

	// Tamper with signature
	tamperedSig := signed + "extra"
	result = signer.Unsign(tamperedSig)
	if result.Valid {
		t.Errorf("Unsign should fail for tampered signature, got valid")
	}
}

func TestSignAndUnsign_UrlEncoding(t *testing.T) {
	secret := "supersecretkey"
	signer := New(secret)

	value := "value/with/special?chars=1&x=2"
	signed := signer.Sign(value)

	// Simulate browser encoding signature
	parts := strings.SplitN(signed, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("Signed value format error: %q", signed)
	}
	valuePart, sigPart := parts[0], parts[1]
	encodedSig := url.QueryEscape(sigPart)
	signedEncoded := valuePart + "." + encodedSig

	result := signer.Unsign(signedEncoded)
	if !result.Valid || result.Value != valuePart {
		t.Errorf("Unsign failed for URL-encoded signature: got valid=%v, value=%q", result.Valid, result.Value)
	}
}

func TestSignAndUnsign2(t *testing.T) {
	secret := "supersecretkey"
	signer := New(secret)

	value := "value/with/special?chars=1&x=2"
	signed := signer.Sign(value)

	// Simulate browser encoding signature
	parts := strings.SplitN(signed, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("Signed value format error: %q", signed)
	}
	valuePart, sigPart := parts[0], parts[1]
	encodedSig := url.QueryEscape(sigPart)
	signedEncoded := valuePart + "." + encodedSig

	result := signer.Unsign(signedEncoded)
	if !result.Valid || result.Value != valuePart {
		t.Errorf("Unsign failed for URL-encoded signature: got valid=%v, value=%q", result.Valid, result.Value)
	}
}