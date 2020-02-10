package server

import (
	"encoding/base64"
	"fmt"

	"github.com/pkg/errors"
)

func (csp *impl) getPublicKey() ([]byte, error) {
	mapData := make(map[string]interface{})
	mapData["id"] = csp.CertID
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetSignCertById.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to request public")
	}

	if res.Code != "0" {
		return nil, errors.New(res.Message)
	}

	bytes, err := base64.StdEncoding.DecodeString(res.Message)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode public")
	}

	return bytes, nil
}

func (csp *impl) getCertTheme() (string, error) {
	publicKey, err := csp.getPublicKey()
	if err != nil {
		return "", errors.Wrap(err, "failed to get public key")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 1
	mapData["certB64"] = base64.StdEncoding.EncodeToString(publicKey)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetCertInfo.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return "", errors.Wrap(err, "failed to request public")
	}

	if res.Code != "0" {
		return "", errors.New(res.Message)
	}

	return res.Message, nil
}

func (csp *impl) getCertSerialNumber() (string, error) {
	publicKey, err := csp.getPublicKey()
	if err != nil {
		return "", errors.Wrap(err, "failed to get public key")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 2
	mapData["certB64"] = base64.StdEncoding.EncodeToString(publicKey)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetCertInfo.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return "", errors.Wrap(err, "failed to request public")
	}

	if res.Code != "0" {
		return "", errors.New(res.Message)
	}

	return res.Message, nil
}

func (csp *impl) getCertIssuerSubject() (string, error) {
	publicKey, err := csp.getPublicKey()
	if err != nil {
		return "", errors.Wrap(err, "failed to get public key")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 3
	mapData["certB64"] = base64.StdEncoding.EncodeToString(publicKey)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetCertInfo.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return "", errors.Wrap(err, "failed to request public")
	}

	if res.Code != "0" {
		return "", errors.New(res.Message)
	}

	return res.Message, nil
}

func (csp *impl) getCertEntity() (string, error) {
	publicKey, err := csp.getPublicKey()
	if err != nil {
		return "", errors.Wrap(err, "failed to get public key")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 14
	mapData["certB64"] = base64.StdEncoding.EncodeToString(publicKey)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetCertInfo.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return "", errors.Wrap(err, "failed to request public")
	}

	if res.Code != "0" {
		return "", errors.New(res.Message)
	}

	return res.Message, nil
}

func (csp *impl) validateCert() (bool, error) {
	publicKey, err := csp.getPublicKey()
	if err != nil {
		return false, errors.Wrap(err, "failed to get public key")
	}

	mapData := make(map[string]interface{})
	mapData["certB64"] = base64.StdEncoding.EncodeToString(publicKey)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/ValidateCert.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return false, errors.Wrap(err, "failed to request public")
	}

	if res.Message == "有效的证书!" {
		return true, nil
	}

	return false, errors.New(res.Message)
}
