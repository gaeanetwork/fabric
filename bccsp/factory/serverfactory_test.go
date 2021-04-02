package factory

import (
	"testing"

	"github.com/hyperledger/fabric/bccsp/server"
	"github.com/stretchr/testify/assert"
)

func TestServerFactoryName(t *testing.T) {
	f := &ServerFactory{}
	assert.Equal(t, f.Name(), ServerBasedFactoryName)
}

func TestServerFactoryGetInvalidArgs(t *testing.T) {
	f := &ServerFactory{}

	_, err := f.Get(nil)
	assert.Error(t, err, "Invalid config. ServerOpts must not be nil")

	_, err = f.Get(&FactoryOpts{})
	assert.Error(t, err, "Invalid config. ServerOpts must not be nil")

	opts := &FactoryOpts{
		ServerOpts: &server.Opts{},
	}
	_, err = f.Get(opts)
	assert.Error(t, err, "CSP:500 - Failed initializing configuration at [0,]")
}

func TestServerFactoryGet(t *testing.T) {
	f := &ServerFactory{}

	opts := &FactoryOpts{
		ServerOpts: &server.Opts{
			SecLevel:   256,
			HashFamily: "SHA2",
		},
	}
	csp, err := f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)

	opts = &FactoryOpts{
		ServerOpts: &server.Opts{
			SecLevel:   256,
			HashFamily: "SHA2",
		},
	}
	csp, err = f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)

	opts = &FactoryOpts{
		ServerOpts: &server.Opts{
			HashFamily: "SM3",
		},
	}
	csp, err = f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)
}
