// Licensed to Andrew Kroh under one or more agreements.
// Andrew Kroh licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package google_oidc_auth_middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type base64er interface {
	Base64() string
}

// cookieSigner encodes and decodes cookies with integrity protection.
type cookieSigner struct {
	key []byte
}

func newCookieSigner(key string) *cookieSigner {
	return &cookieSigner{key: []byte(key)}
}

func (s *cookieSigner) Encode(cookie base64er) (string, error) {
	// NOTE: This interface is only necessary under Yaegi. Passing a
	// generic interface{} value breaks the ability to encode. Even
	// json.Marshal fails in a strange way by returning '{}'.
	v := cookie.Base64()

	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(v))
	sig := base64.RawURLEncoding.EncodeToString(m.Sum(nil))

	return sig + "." + v, nil
}

func (s *cookieSigner) Decode(data string, value any) error {
	parts := strings.Split(data, ".")
	if len(parts) != 2 {
		return errors.New("malformed value: expected 2 parts")
	}
	sig := parts[0]
	v := parts[1]

	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(v))
	computedSig := base64.RawURLEncoding.EncodeToString(m.Sum(nil))

	if computedSig != sig {
		return errInvalidCookieSignature
	}

	jsonBytes, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return fmt.Errorf("failed decoding base64 cookie value: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.UseNumber()
	return dec.Decode(value)
}
