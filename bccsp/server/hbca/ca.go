package hbca

import (
	"encoding/base64"
	"fmt"

	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
)

func (csp *HuBeiCa) getCertBase64() (string, error) {
	mapData := make(map[string]interface{})
	mapData["id"] = csp.CertID
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetSignCertById.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return "", errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return "", errors.New(res.Message)
	}

	return res.Message, nil
}

func (csp *HuBeiCa) getCertInfo() (*sm2.Certificate, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return nil, errors.Wrap(err, "csp.getCertBase64()")
	}

	bytes, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(res.Message)")
	}

	cert, err := sm2.ParseCertificate(bytes)
	if err != nil {
		return nil, errors.Wrap(err, "sm2.ParseCertificate(publicKeyBytes)")
	}
	return cert, nil
}

func (csp *HuBeiCa) getCertTheme() (string, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return "", errors.Wrap(err, "csp.getCertBase64()")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 1
	mapData["certB64"] = certBase64
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret

	url := fmt.Sprintf("%s://%s/hbcaDSS/GetCertInfo.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return "", errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return "", errors.New(res.Message)
	}

	return res.Message, nil
}

func (csp *HuBeiCa) getCertSerialNumber() (string, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return "", errors.Wrap(err, "csp.getCertBase64()")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 2
	mapData["certB64"] = certBase64
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

func (csp *HuBeiCa) getCertIssuerSubject() (string, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return "", errors.Wrap(err, "csp.getCertBase64()")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 3
	mapData["certB64"] = certBase64
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

func (csp *HuBeiCa) getCertEntity() (string, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return "", errors.Wrap(err, "csp.getCertBase64()")
	}

	mapData := make(map[string]interface{})
	mapData["type"] = 14
	mapData["certB64"] = certBase64
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

func (csp *HuBeiCa) validateCert() (bool, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return false, errors.Wrap(err, "csp.getCertBase64()")
	}

	mapData := make(map[string]interface{})
	mapData["certB64"] = certBase64
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

func (csp *HuBeiCa) singData(input []byte) ([]byte, error) {
	mapData := make(map[string]interface{})
	mapData["signedCertAlias"] = fmt.Sprint(csp.CertID)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret
	mapData["inData"] = base64.StdEncoding.EncodeToString(input)
	mapData["digestAlg"] = "SM3WITHSM2"

	url := fmt.Sprintf("%s://%s/hbcaDSS/SignData.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return nil, errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return nil, errors.New(res.Message)
	}

	output, err := base64.StdEncoding.DecodeString(res.Message)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(res.Message)")
	}
	return output, nil
}

func (csp *HuBeiCa) verifySignedData(input, signBytes []byte) (bool, error) {
	certBase64, err := csp.getCertBase64()
	if err != nil {
		return false, errors.Wrap(err, "csp.getCertBase64()")
	}

	mapData := make(map[string]interface{})
	mapData["signedCertAlias"] = fmt.Sprint(csp.CertID)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret
	mapData["inData"] = base64.StdEncoding.EncodeToString(input)
	mapData["digestAlg"] = "SM3WITHSM2"
	mapData["signData"] = base64.StdEncoding.EncodeToString(signBytes)
	mapData["certB64"] = certBase64

	url := fmt.Sprintf("%s://%s/hbcaDSS/VerifySignedData.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return false, errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return false, errors.New(res.Message)
	}

	return true, nil
}

func (csp *HuBeiCa) pubKeyEncrypt(input []byte) ([]byte, error) {
	mapData := make(map[string]interface{})
	mapData["encryptCertAlias"] = fmt.Sprint(csp.CertID)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret
	mapData["inData"] = base64.StdEncoding.EncodeToString(input)

	url := fmt.Sprintf("%s://%s/hbcaDSS/PubKeyEncrypt.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return nil, errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return nil, errors.New(res.Message)
	}

	output, err := base64.StdEncoding.DecodeString(res.Message)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(res.Message)")
	}
	return output, nil
}

func (csp *HuBeiCa) priKeyDecrypt(input []byte) ([]byte, error) {
	mapData := make(map[string]interface{})
	mapData["decryptCertAlias"] = fmt.Sprint(csp.CertID)
	mapData["appKey"] = csp.AppKey
	mapData["appSecret"] = csp.AppSecret
	mapData["inData"] = base64.StdEncoding.EncodeToString(input)

	url := fmt.Sprintf("%s://%s/hbcaDSS/PriKeyDecrypt.do", csp.Protocol, csp.HTTPServer)
	res, err := httpRequestJSON("POST", url, mapData)
	if err != nil {
		return nil, errors.Wrap(err, "httpRequestJSON(\"POST\", url, mapData)")
	}

	if res.Code != "0" {
		return nil, errors.New(res.Message)
	}

	output, err := base64.StdEncoding.DecodeString(res.Message)
	if err != nil {
		return nil, errors.Wrap(err, "base64.StdEncoding.DecodeString(res.Message)")
	}
	return output, nil
}
