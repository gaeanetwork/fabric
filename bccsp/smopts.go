package bccsp

import "io"

// SM3Opts contains options for SM3.
type SM3Opts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM3Opts) Algorithm() string {
	return SM3
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM3Opts) Ephemeral() bool {
	return opts.Temporary
}

// SM4Opts contains options for SM4.
type SM4Opts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM4Opts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM4Opts) Ephemeral() bool {
	return opts.Temporary
}

// SM4CBCPKCS7ModeOpts contains options for sm4 encryption in CBC mode
// with PKCS7 padding.
// Notice that both IV and PRNG can be nil. In that case, the BCCSP implementation
// is supposed to sample the IV using a cryptographic secure PRNG.
// Notice also that either IV or PRNG can be different from nil.
type SM4CBCPKCS7ModeOpts struct {
	// IV is the initialization vector to be used by the underlying cipher.
	// The length of IV must be the same as the Block's block size.
	// It is used only if different from nil.
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}
