package server

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/server/hbca"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/pkg/errors"
)

// New new a server bccsp
func New(opts *Opts, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(opts.SecLevel, opts.HashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration")
	}

	swCSP, err := sw.NewWithParams(opts.SecLevel, opts.HashFamily, keyStore)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing fallback SW BCCSP")
	}

	// Check KeyStore
	if keyStore == nil {
		return nil, errors.New("Invalid bccsp.KeyStore instance. It must be different from nil")
	}

	csp := &impl{swCSP, conf, keyStore}
	switch opts.DefaultOpts {
	case "hbca":
		csp.implcsp = newhbca(opts)
	default:
		return nil, errors.Wrapf(err, "unsupport opts of server type")
	}
	return csp, nil
}

func newhbca(opts *Opts) bccsp.BCCSP {
	return &hbca.HuBeiCa{
		HTTPServer: opts.HTTPServer,
		Protocol:   opts.Protocol,
		CertID:     opts.CertID,
		AppKey:     opts.AppKey,
		AppSecret:  opts.AppSecret,
	}
}
