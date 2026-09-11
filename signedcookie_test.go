// Licensed to Andrew Kroh under one or more agreements.
// Andrew Kroh licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package google_oidc_auth_middleware

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type myType struct {
	User string `json:"user"`
}

func (m myType) Base64() string {
	j, _ := json.Marshal(m)
	return base64.RawURLEncoding.EncodeToString(j)
}

func TestSignedCookie(t *testing.T) {
	s := &cookieSigner{key: []byte("hello")}

	value := &myType{User: "john"}

	signedValue, err := s.Encode(value)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(signedValue, ".")
	if len(parts) != 2 {
		t.Fatalf("encoded cookie %q does not have 2 parts", signedValue)
	}
	sig, encodedValue := parts[0], parts[1]

	// Flip the bits of the first MAC byte to get a well formed but wrong
	// signature.
	mac, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	mac[0] ^= 0xff
	tamperedSig := base64.RawURLEncoding.EncodeToString(mac)

	otherKeySigner := &cookieSigner{key: []byte("goodbye")}
	otherKeyValue, err := otherKeySigner.Encode(value)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		data    string
		wantErr error
	}{
		{
			name: "valid signature",
			data: signedValue,
		},
		{
			name:    "tampered signature",
			data:    tamperedSig + "." + encodedValue,
			wantErr: errInvalidCookieSignature,
		},
		{
			name:    "signature is not base64",
			data:    "not base64!!." + encodedValue,
			wantErr: errInvalidCookieSignature,
		},
		{
			name:    "empty signature",
			data:    "." + encodedValue,
			wantErr: errInvalidCookieSignature,
		},
		{
			name:    "signed with a different key",
			data:    otherKeyValue,
			wantErr: errInvalidCookieSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var decodeValue *myType
			err := s.Decode(tt.data, &decodeValue)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("want=%v got=%v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(value, decodeValue) {
				t.Errorf("want=%+v got=%+v", value, decodeValue)
			}
		})
	}
}
