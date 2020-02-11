package server

import "github.com/hyperledger/fabric/bccsp"

func (csp *impl) signSM2(digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return csp.singData(digest)
}

func (csp *impl) verifySM2(signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return csp.verifySignedData(digest, signature)
}
