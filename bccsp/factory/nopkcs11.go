// +build !pkcs11

/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/server"
	"github.com/pkg/errors"
)

// FactoryOpts holds configuration information used to initialize factory implementations
type FactoryOpts struct {
	ProviderName string       `mapstructure:"default" json:"default" yaml:"Default"`
	SwOpts       *SwOpts      `mapstructure:"SW,omitempty" json:"SW,omitempty" yaml:"SwOpts"`
	PluginOpts   *PluginOpts  `mapstructure:"PLUGIN,omitempty" json:"PLUGIN,omitempty" yaml:"PluginOpts"`
	ServerOpts   *server.Opts `mapstructure:"Server,omitempty" json:"server,omitempty" yaml:"server"`
}

// InitFactories must be called before using factory interfaces
// It is acceptable to call with config = nil, in which case
// some defaults will get used
// Error is returned only if defaultBCCSP cannot be found
func InitFactories(config *FactoryOpts) error {
	factoriesInitOnce.Do(func() {
		// Take some precautions on default opts
		if config == nil {
			config = GetDefaultOpts()
		}

		if config.ProviderName == "" {
			config.ProviderName = SoftwareBasedFactoryName
		}

		if config.SwOpts == nil {
			config.SwOpts = GetDefaultOpts().SwOpts
		}

		// Initialize factories map
		bccspMap = make(map[string]bccsp.BCCSP)

		// Software-Based BCCSP
		if config.SwOpts != nil {
			f := &SWFactory{}
			err := initBCCSP(f, config)
			if err != nil {
				factoriesInitError = errors.Wrapf(err, "Failed initializing BCCSP.")
			}
		}

		// BCCSP Plugin
		if config.PluginOpts != nil {
			f := &PluginFactory{}
			err := initBCCSP(f, config)
			if err != nil {
				factoriesInitError = errors.Wrapf(err, "Failed initializing PKCS11.BCCSP %s", factoriesInitError)
			}
		}

		// BCCSP ServerOpts
		if config.ServerOpts != nil {
			f := &ServerFactory{}
			err := initBCCSP(f, config)
			if err != nil {
				factoriesInitError = errors.Wrapf(err, "Failed initializing Server.BCCSP %s", factoriesInitError)
			}
		}

		var ok bool
		defaultBCCSP, ok = bccspMap[config.ProviderName]
		if !ok {
			factoriesInitError = errors.Errorf("%s\nCould not find default `%s` BCCSP", factoriesInitError, config.ProviderName)
		}
	})

	return factoriesInitError
}

// GetBCCSPFromOpts returns a BCCSP created according to the options passed in input.
func GetBCCSPFromOpts(config *FactoryOpts) (bccsp.BCCSP, error) {
	var f BCCSPFactory
	switch config.ProviderName {
	case SoftwareBasedFactoryName:
		f = &SWFactory{}
	case PluginFactoryName:
		f = &PluginFactory{}
	case ServerBasedFactoryName:
		f = &ServerFactory{}
	default:
		return nil, errors.Errorf("Could not find BCCSP, no '%s' provider", config.ProviderName)
	}

	csp, err := f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}
