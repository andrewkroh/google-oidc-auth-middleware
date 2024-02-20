// Licensed to Andrew Kroh under one or more agreements.
// Andrew Kroh licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package google_oidc_auth_middleware

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
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

	var decodeValue *myType
	err = s.Decode(signedValue, &decodeValue)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(value, decodeValue) {
		t.Errorf("want=%+v got=%+v", value, decodeValue)
	}
}
