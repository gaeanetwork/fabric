package server

import "github.com/hyperledger/fabric/bccsp"

func (csp *impl) signSM2(k sm2PrivateKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (csp *impl) verifySM2(k sm2PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return true, nil
}
