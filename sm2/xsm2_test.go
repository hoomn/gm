package sm2

import (
	"testing"
)

func TestBHGenerateKey(t *testing.T) {
	publicKey, privateKey, err := BHGenerateKey()
	if err != nil {
		t.Log(err)
	}
	t.Logf("---BHGenerateKey---\npubKey:%s\nprivateKey:%s\n", publicKey, privateKey)
}

func TestPointCompressSignVerify(t *testing.T) {
	publicKey, privateKey, err := BHGeneratePointCompressKey()
	if err != nil {
		t.Fail()
	}
	data := []byte("hello,i'm dongdong")
	sign, err := BHSign(privateKey, nil, data)

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	result, err := BHVerifyWithPointCompress(publicKey, nil, data, sign)

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	if !result {
		t.Fail()
	}
}

func TestPointCompressSigVerifyAsn1(t *testing.T) {
	publicKey, privateKey, err := BHGeneratePointCompressKey()
	if err != nil {
		t.Fail()
	}
	data := []byte("hello,i'm dongdong")
	sign, err := BHSignX(privateKey, nil, data)

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	result, err := BHVerifyWithPointCompressX(publicKey, nil, data, sign)

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	if !result {
		t.Fail()
	}
}

func TestSigVerify(t *testing.T) {
	publicKey, privateKey, err := BHGenerateKey()
	if err != nil {
		t.Fail()
	}
	data := []byte("hello,i'm dongdong")
	sign, err := BHSign(privateKey, nil, data)

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	result, err := BHVerify(publicKey, nil, data, sign)

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	if !result {
		t.Fail()
	}
}

func TestSignVerifyAsn1(t *testing.T) {
	publicKey, privateKey, err := BHGenerateKey()
	if err != nil {
		t.Fail()
	}
	data := []byte("hello,i'm dongdong")
	sign, err := BHSignX(privateKey, nil, data)

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	result, err := BHVerifyX(publicKey, nil, data, sign)

	if err != nil {
		t.Error(err)
		t.Fail()
	}

	if !result {
		t.Fail()
	}
}
