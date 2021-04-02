/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bccsp

import (
	"fmt"
)

// IdemixIIssuerPublicKeyImporterErrorType ...
type IdemixIIssuerPublicKeyImporterErrorType int

const (
	// IdemixIssuerPublicKeyImporterUnmarshallingError ...
	IdemixIssuerPublicKeyImporterUnmarshallingError IdemixIIssuerPublicKeyImporterErrorType = iota
	// IdemixIssuerPublicKeyImporterHashError ...
	IdemixIssuerPublicKeyImporterHashError
	// IdemixIssuerPublicKeyImporterValidationError ...
	IdemixIssuerPublicKeyImporterValidationError
	// IdemixIssuerPublicKeyImporterNumAttributesError ...
	IdemixIssuerPublicKeyImporterNumAttributesError
	// IdemixIssuerPublicKeyImporterAttributeNameError ...
	IdemixIssuerPublicKeyImporterAttributeNameError
)

// IdemixIssuerPublicKeyImporterError ...
type IdemixIssuerPublicKeyImporterError struct {
	Type     IdemixIIssuerPublicKeyImporterErrorType
	ErrorMsg string
	Cause    error
}

func (r *IdemixIssuerPublicKeyImporterError) Error() string {
	if r.Cause != nil {
		return fmt.Sprintf("%s: %s", r.ErrorMsg, r.Cause)
	}

	return r.ErrorMsg
}
