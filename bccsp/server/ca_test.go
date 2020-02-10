package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func testImp() *impl {
	return &impl{
		Protocol:   "http",
		HTTPServer: "221.232.224.75:8082",
		CertID:     109,
		AppKey:     "TESTAPPKEY",
		AppSecret:  "TESTAPPSECRECT",
	}
}

func testErrorImp() *impl {
	return &impl{
		Protocol:   "http",
		HTTPServer: "221.232.224.75:8082",
		CertID:     10259,
		AppKey:     "TESTAPPKEY",
		AppSecret:  "TESTAPPSECRECT",
	}
}

func Test_GetPublicKey(t *testing.T) {
	implTest := testImp()

	publicKeyBytes, err := implTest.getPublicKey()
	assert.Nil(t, err)
	assert.NotEmpty(t, publicKeyBytes)

	impError := testErrorImp()
	ErrorPublicKeyBytes, err := impError.getPublicKey()
	assert.Error(t, err)
	assert.Nil(t, ErrorPublicKeyBytes)
}

func Test_ValidateCert(t *testing.T) {
	implTest := testImp()

	ok, err := implTest.validateCert()
	assert.Nil(t, err)
	assert.True(t, ok)

	impError := testErrorImp()
	ok, err = impError.validateCert()
	assert.Error(t, err)
	assert.False(t, ok)
}
