package server

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/tjfoc/gmsm/sm3"
	"golang.org/x/crypto/sha3"
)

type config struct {
	hashFunction func() hash.Hash
}

func (conf *config) setSecurityLevel(securityLevel int, hashFamily string) (err error) {
	switch hashFamily {
	case "SHA2":
		err = conf.setSecurityLevelSHA2(securityLevel)
	case "SHA3":
		err = conf.setSecurityLevelSHA3(securityLevel)
	case "SM3":
		err = conf.setSecurityLevelSM3()
	default:
		err = fmt.Errorf("Hash Family not supported [%s]", hashFamily)
	}
	return
}

func (conf *config) setSecurityLevelSHA2(level int) (err error) {
	switch level {
	case 256:
		conf.hashFunction = sha256.New
	case 384:
		conf.hashFunction = sha512.New384
	default:
		err = fmt.Errorf("Security level not supported [%d]", level)
	}
	return
}

func (conf *config) setSecurityLevelSHA3(level int) (err error) {
	switch level {
	case 256:
		conf.hashFunction = sha3.New256
	case 384:
		conf.hashFunction = sha3.New384
	default:
		err = fmt.Errorf("Security level not supported [%d]", level)
	}
	return
}

func (conf *config) setSecurityLevelSM3() (err error) {
	conf.hashFunction = sm3.New
	return
}

// Opts contains options for the P11Factory
type Opts struct {
	// Default algorithms when not specified (Deprecated?)
	SecLevel   int    `mapstructure:"security" json:"security"`
	HashFamily string `mapstructure:"hash" json:"hash"`

	// Keystore options
	// Ephemeral bool `mapstructure:"tempkeys,omitempty" json:"tempkeys,omitempty"`
	// FileKeystore  *FileKeystoreOpts  `mapstructure:"filekeystore,omitempty" json:"filekeystore,omitempty"`
	// DummyKeystore *DummyKeystoreOpts `mapstructure:"dummykeystore,omitempty" json:"dummykeystore,omitempty"`

	// PKCS11 options
	HTTPServer string `mapstructure:"httpserver" json:"httpserver"`
	Protocol   string `mapstructure:"protocol" json:"protocol"`
	CertName   string `mapstructure:"certName" json:"certName"`
	CertB64    string `mapstructure:"certB64" json:"certB64"`
	AppKey     string `mapstructure:"appKey" json:"appKey"`
	AppSecret  string `mapstructure:"appSecret" json:"appSecret"`
}
