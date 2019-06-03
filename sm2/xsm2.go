package sm2

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
)

// BHGeneratePointCompressKey used to product publicKey and privateKey.
// The publicKey is ponit compressed
func BHGeneratePointCompressKey() (pubKey string, priKey string, err error) {
	priv, pub, err := GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	pubKeyHex := hex.EncodeToString(compress(pub))
	priKeyHex := hex.EncodeToString(priv.GetRawBytes())
	return pubKeyHex, priKeyHex, nil
}

// BHGenerateKey used to product publicKey and privateKey
func BHGenerateKey() (pubKey string, priKey string, err error) {
	priv, pub, err := GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	pubKeyHex := hex.EncodeToString(pub.GetRawBytes())
	priKeyHex := hex.EncodeToString(priv.GetRawBytes())
	return pubKeyHex, priKeyHex, nil
}

// BHSign used to sign src,priKey is hex string.return r/s bytes
// If userID be assigned nil,which  default value is 1234567812345678
func BHSign(priKey string, userID []byte, src []byte) ([]byte, error) {
	priKeyBytes, err := hex.DecodeString(priKey)
	if err != nil {
		return nil, errors.New("decode privateStr fail")
	}

	privateKey, err := RawBytesToPrivateKey(priKeyBytes)
	if err != nil {
		return nil, errors.New("convert privKey bytes to PrivateKey fail")
	}
	r, s, err := SignToRS(privateKey, userID, src)
	if err != nil {
		return nil, errors.New("SignToRS fail")
	}
	result := bytesCombine(r.Bytes(), s.Bytes())
	return result, nil
}

func bytesCombine(pBytes ...[]byte) []byte {
	len := len(pBytes)
	s := make([][]byte, len)
	for index := 0; index < len; index++ {
		s[index] = pBytes[index]
	}
	sep := []byte("")
	return bytes.Join(s, sep)
}

// BHSignX used to sign src,priKey is hex string.return asn.1 format bytes
// If userID be assigned nil,which  default value is 1234567812345678
func BHSignX(priKey string, userID []byte, src []byte) ([]byte, error) {
	priKeyBytes, err := hex.DecodeString(priKey)
	if err != nil {
		return nil, errors.New("decode privateStr fail")
	}

	privateKey, err := RawBytesToPrivateKey(priKeyBytes)
	if err != nil {
		return nil, errors.New("convert privKey bytes to PrivateKey fail")
	}
	result, err := Sign(privateKey, userID, src)
	if err != nil {
		return nil, errors.New("sign fail")
	}
	return result, nil
}

// BHVerifyWithPointCompress used to verify src and sign,the pubKey is point compress,the sign is r/s bytes
// If userID be assigned nil,which  default value is 1234567812345678
func BHVerifyWithPointCompress(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error) {
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return false, err
	}

	publicKey := decompress(pubKeyBytes)
	r := new(big.Int).SetBytes(sign[:KeyBytes])
	s := new(big.Int).SetBytes(sign[KeyBytes:])
	return VerifyByRS(publicKey, userID, src, r, s), nil
}

// BHVerifyWithPointCompressX used to verify src and sign,the pubKey is point compress,the sign is asn.1 format bytes
// If userID be assigned nil,which  default value is 1234567812345678
func BHVerifyWithPointCompressX(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error) {
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return false, err
	}

	publicKey := decompress(pubKeyBytes)
	return Verify(publicKey, userID, src, sign), nil
}

// BHVerify function is similar with VerifyWithPointCompress,the pubKey is unCompress,the sign is r/s bytes
func BHVerify(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error) {
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return false, err
	}
	publicKey, err := RawBytesToPublicKey(pubKeyBytes)
	if err != nil {
		return false, err
	}
	r := new(big.Int).SetBytes(sign[:KeyBytes])
	s := new(big.Int).SetBytes(sign[KeyBytes:])
	return VerifyByRS(publicKey, userID, src, r, s), nil
}

// BHVerifyX function is similar with VerifyWithPointCompress,the pubKey is unCompress,the sign is asn.1 format bytes
func BHVerifyX(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error) {
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return false, err
	}
	publicKey, err := RawBytesToPublicKey(pubKeyBytes)
	if err != nil {
		return false, err
	}
	return Verify(publicKey, userID, src, sign), nil
}

func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

func getLastBit(a *big.Int) uint {
	return a.Bit(0)
}

func compress(a *PublicKey) []byte {
	buf := []byte{}
	yp := getLastBit(a.Y)
	buf = append(buf, a.X.Bytes()...)
	if n := len(a.X.Bytes()); n < 32 {
		buf = append(zeroByteSlice()[:(32-n)], buf...)
	}
	buf = append([]byte{byte(yp)}, buf...)
	return buf
}

func decompress(a []byte) *PublicKey {
	var aa, xx, xx3 sm2P256FieldElement

	P256Sm2()
	x := new(big.Int).SetBytes(a[1:])
	curve := sm2P256
	sm2P256FromBig(&xx, x)
	sm2P256Square(&xx3, &xx)       // x3 = x ^ 2
	sm2P256Mul(&xx3, &xx3, &xx)    // x3 = x ^ 2 * x
	sm2P256Mul(&aa, &curve.a, &xx) // a = a * x
	sm2P256Add(&xx3, &xx3, &aa)
	sm2P256Add(&xx3, &xx3, &curve.b)

	y2 := sm2P256ToBig(&xx3)
	y := new(big.Int).ModSqrt(y2, sm2P256.P)
	if getLastBit(y) != uint(a[0]) {
		y.Sub(sm2P256.P, y)
	}
	return &PublicKey{
		Curve: GetSm2P256V1(),
		X:     x,
		Y:     y,
	}
}
