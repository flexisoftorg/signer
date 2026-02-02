# Signer

A Go library for signing and unsigning cookie values, compatible with [@fastify/cookie](https://github.com/fastify/fastify-cookie).

Inspired by [node-cookie-signature](https://github.com/tj/node-cookie-signature).

## Installation

```bash
go get github.com/brage/signer
```

## Usage

```go
package main

import (
    "fmt"
    "github.com/brage/signer"
)

func main() {
    signer := signer.New("your-secret")
    signed := signer.Sign("cookie-value")
    result := signer.Unsign(signed)
    if result.Valid {
        fmt.Println(result.Value) // "cookie-value"
    }
}
```

## API

### New(secrets ...string) *Signer

Creates a new Signer with the given secrets. The first secret is used for signing, all secrets are used for unsigning (supports key rotation).

### Sign(value string) string

Signs a value and returns the signed string in format: `value.signature`

### Unsign(signedValue string) UnsignResult

Verifies and extracts the value from a signed string.

### UnsignResult

```go
type UnsignResult struct {
    Valid bool   // true if the signature is valid
    Renew bool   // true if signed with a non-primary secret (for key rotation)
    Value string // the unsigned value, empty if invalid
}
```

## License

MIT