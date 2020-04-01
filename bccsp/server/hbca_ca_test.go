package server

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm2"
)

func testImp() (*HuBeiCa, error) {
	hbca := &HuBeiCa{
		opt: &HBCAOpts{
			WSDLServer: "http://221.232.224.75:8082/hbcaDSS/hbcaService?wsdl",
			CertID:     "109",
			AppKey:     "TESTAPPKEY",
			AppSecret:  "TESTAPPSECRECT",
		},
		CertServer: "http://221.232.224.75:58140",
	}
	return hbca, nil
}

func testErrorImp() *HuBeiCa {
	return &HuBeiCa{
		opt: &HBCAOpts{
			WSDLServer: "http://221.232.224.75:8082/hbcaDSS/hbcaService?wsdl",
			CertID:     "10259",
			AppKey:     "TESTAPPKEY",
			AppSecret:  "TESTAPPSECRECT",
		},
	}
}

func Test_CA_GetCertBase64(t *testing.T) {
	implTest, err := testImp()
	assert.Nil(t, err)

	certBase64, err := implTest.GetCertBase64("109")
	assert.Nil(t, err)
	assert.NotEmpty(t, certBase64)

	impError := testErrorImp()
	ErrorPublicKeyBytes, err := impError.GetCertBase64("109")
	assert.Error(t, err)
	assert.Empty(t, ErrorPublicKeyBytes)
}

func Test_CA_GetCertInfo(t *testing.T) {
	implTest, err := testImp()
	assert.Nil(t, err)

	cert, err := implTest.GetCertInfo("109")
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	bytes, err := sm2.MarshalPKIXPublicKey(cert.PublicKey)
	assert.Nil(t, err)

	pk, err := sm2.ParseSm2PublicKey(bytes)
	assert.Nil(t, err)
	assert.NotNil(t, pk)

	impError := testErrorImp()
	errorCert, err := impError.GetCertInfo("109")
	assert.Error(t, err)
	assert.Nil(t, errorCert)
}

func Test_CA_SignAndVerifyData(t *testing.T) {
	implTest, err := testImp()
	assert.Nil(t, err)

	inData := []byte("123456")
	outputBytes, err := implTest.SignData("", inData)
	assert.Nil(t, err)
	assert.NotNil(t, outputBytes)

	ok, err := implTest.VerifySignedData(inData, outputBytes)
	assert.Nil(t, err)
	assert.True(t, ok)

	errInData := []byte("1234567")
	ok, err = implTest.VerifySignedData(errInData, outputBytes)
	assert.NotNil(t, err)
	assert.False(t, ok)

	errSingData := []byte("1234567")
	ok, err = implTest.VerifySignedData(inData, errSingData)
	assert.NotNil(t, err)
	assert.False(t, ok)
}

func Test_CA_pubKeyEncryptAndPriKeyDecrypt(t *testing.T) {
	implTest, err := testImp()
	assert.Nil(t, err)

	inData := []byte("123456")
	ciphertext, err := implTest.PubKeyEncrypt(inData)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)

	plaintext, err := implTest.PriKeyDecrypt(ciphertext)
	assert.Nil(t, err)
	assert.True(t, bytes.Equal(inData, plaintext))

	errInData := []byte("1234567")
	plaintext, err = implTest.PriKeyDecrypt(errInData)
	assert.NotNil(t, err)
	assert.False(t, bytes.Equal(inData, plaintext))
}

func Test_CA_Apply(t *testing.T) {
	implTest, err := testImp()
	assert.Nil(t, err)

	// 1、apply p10
	// ApplyDn format "CN=Hbca_test333_4,C=CN"
	createP10Input := &CreateP10Input{
		CertID:     hex.EncodeToString([]byte(uuid.New().String())),
		CertName:   hex.EncodeToString([]byte(uuid.New().String())),
		ApplyDn:    "CN=Hbca_test333_4,C=CN",
		EncryptAlg: "SM2",
		KeyLength:  "256",
		DigestAlg:  "SHA1",
	}

	res, err := implTest.CreateP10(createP10Input)
	assert.Nil(t, err)
	assert.NotEmpty(t, res)

	// time.Sleep(1 * time.Minute)
	p10 := res
	// 2、apply ca
	input := &HBCAApplyInput{
		CreditCode:           uuid.New().String()[0:8],
		UnitName:             "平原省津浦区",
		UnitAddress:          "中原大道56号",
		LegalName:            "林中木_4",
		LegalID:              "4109231965022645674",
		LegalPhone:           "15321625945",
		ProvinceCode:         "987456",
		PrefecturalLevelCity: "新乡市",
		Stproperty:           "平原省",
		UnitProperty:         "信息产业改革委员会",
		Location:             "食顷大厦2层",
		ESID:                 "esId",
		P10:                  p10,
		DoubleP10:            p10,
		AuthUserID:           "5962918001A8457D96251A215E3CC0D8",
		PlatformName:         "测试平台系统",
		CertDn:               "测试DN1",
	}

	responseApply, err := implTest.CertApply(input)
	assert.Nil(t, err)

	// importEncCert := &ImportEncCert{
	// 	RootID:          "SM2Test",
	// 	SignCertID:      certID,
	// 	EncCertID:       certID,
	// 	EncCertB64:      responseApply.Data.EncryptCert,
	// 	DoubleEncPriKey: responseApply.Data.DoubleEncryptedPrivateKey,
	// 	CertType:        "SM2",
	// }
	// responseImportEncCert, err := implTest.ImportEncCert(importEncCert)
	// assert.Nil(t, err)
	// fmt.Println(responseImportEncCert)

	// signCertB64 := ""
	// certType = ""
	// rootCertName := ""
	// importType := ""
	// password := ""
	// responseImportSignCert, err := implTest.ImportSignCert(certID, certName, signCertB64, certType, rootCertName, importType, password)
	// assert.Nil(t, err)
	// fmt.Println(responseImportSignCert)

	extendCertInput := &ExtendCertInput{
		CaData: &RefCode{
			RefCode: responseApply.Data.RefCode,
		},
		ESID:         "esID",
		BeginTime:    "beginTime",
		EndTime:      "endTime",
		MonthTime:    "mothTime",
		P10:          p10,
		DoubleP10:    p10,
		AuthUserID:   "5962918001A8457D96251A215E3CC0D8",
		PlatformName: "测试平台系统",
		CertDn:       "测试DN1",
	}

	resExtend, err := implTest.ExtendCertValid(extendCertInput)
	assert.Nil(t, err)
	assert.NotNil(t, resExtend)

	certRevokeInput := &CertRevokeInput{
		CaData: &RefCode{
			RefCode: resExtend.Data.RefCode,
		},
		RevokeDesc:   "1212",
		AuthUserID:   "5962918001A8457D96251A215E3CC0D8",
		PlatformName: "测试平台系统",
		CertDn:       "测试DN1",
	}
	err = implTest.CertRevoke(certRevokeInput)
	assert.Nil(t, err)
}
