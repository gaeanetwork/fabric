package hbca

import (
	"hash"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm3"
)

// HuBeiCa a ca type
type HuBeiCa struct {
	HTTPServer string
	Protocol   string
	CertID     int64
	AppKey     string
	AppSecret  string
}

// KeyGen generates a key using opts.
func (csp *HuBeiCa) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	return nil, nil
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *HuBeiCa) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	return nil, nil
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *HuBeiCa) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	return
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *HuBeiCa) GetKey(ski []byte) (k bccsp.Key, err error) {
	return
}

// Hash hashes messages msg using options opts.
func (csp *HuBeiCa) Hash(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	digest = sm3.Sm3Sum(msg)
	return
}

// GetHash returns and instance of hash.Hash using options opts.
// If opts is nil then the default hash function is returned.
func (csp *HuBeiCa) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	h = sm3.New()
	return
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *HuBeiCa) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty")
	}

	if ok, err := csp.validateCert(); err != nil {
		return nil, errors.Wrap(err, "csp.validateCert()")
	} else if !ok {
		return nil, errors.New("Invalid cert")
	}

	return csp.singData(digest)
}

// Verify verifies signature against key k and digest
func (csp *HuBeiCa) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty")
	}

	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty")
	}

	if ok, err := csp.validateCert(); err != nil {
		return false, errors.Wrap(err, "csp.validateCert()")
	} else if !ok {
		return false, errors.New("Invalid cert")
	}

	return csp.verifySignedData(signature, digest)
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *HuBeiCa) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	if ok, err := csp.validateCert(); err != nil {
		return nil, errors.Wrap(err, "csp.validateCert()")
	} else if !ok {
		return nil, errors.New("Invalid cert")
	}

	// TODO: Add PKCS11 support for encryption, when fabric starts requiring it
	return csp.pubKeyEncrypt(plaintext)
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *HuBeiCa) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	if ok, err := csp.validateCert(); err != nil {
		return nil, errors.Wrap(err, "csp.validateCert()")
	} else if !ok {
		return nil, errors.New("Invalid cert")
	}

	return csp.priKeyDecrypt(ciphertext)
}
