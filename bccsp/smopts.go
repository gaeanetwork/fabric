package bccsp

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
