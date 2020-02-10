package server

import (
	"errors"

	"github.com/hyperledger/fabric/bccsp"
)

type impl struct {
	bccsp.BCCSP

	conf *config
	ks   bccsp.KeyStore

	HTTPServer string
	Protocol   string
	CertID     int64
	AppKey     string
	AppSecret  string
}

// KeyGen generates a key using opts.
func (csp *impl) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil")
	}

	return k, nil
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. Cannot be nil")
	}

	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil")
	}
	return
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *impl) GetKey(ski []byte) (bccsp.Key, error) {

	return csp.BCCSP.GetKey(ski)
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *impl) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty")
	}

	return nil, nil
}

// Verify verifies signature against key k and digest
func (csp *impl) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty")
	}

	return false, nil
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	// TODO: Add PKCS11 support for encryption, when fabric starts requiring it
	return csp.BCCSP.Encrypt(k, plaintext, opts)
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *impl) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	return csp.BCCSP.Decrypt(k, ciphertext, opts)
}
