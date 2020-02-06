package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/server"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/pkg/errors"
)

const (
	// ServerBasedFactoryName is the name of the factory of the hsm-based BCCSP implementation
	ServerBasedFactoryName = "SERVER"
)

// ServerFactory is the factory of the HSM-based BCCSP.
type ServerFactory struct{}

// Name returns the name of this factory
func (f *ServerFactory) Name() string {
	return ServerBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *ServerFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.ServerOpts == nil {
		return nil, errors.New("Invalid config. ServerOpts must not be nil")
	}

	ks := sw.NewInMemoryKeyStore()
	return server.New(config.ServerOpts, ks)
}
