package sm2

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
)

// GeneratePointCompressKeyX used to product publicKey and privateKey.
// The publicKey is ponit compressed
func GeneratePointCompressKeyX() (pubKey string, priKey string, err error) {
	priv, pub, err := GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	pubKeyHex := hex.EncodeToString(compress(pub))
	priKeyHex := hex.EncodeToString(priv.GetRawBytes())
	return pubKeyHex, priKeyHex, nil
}

// GenerateKeyX used to product publicKey and privateKey
func GenerateKeyX() (pubKey string, priKey string, err error) {
	priv, pub, err := GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	pubKeyHex := hex.EncodeToString(pub.GetRawBytes())
	priKeyHex := hex.EncodeToString(priv.GetRawBytes())
	return pubKeyHex, priKeyHex, nil
}

// SignX used to sign src,priKey is hex string.
// If userID be assigned nil,which  default value is 1234567812345678
func SignX(priKey string, userID []byte, src []byte) ([]byte, error) {
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

// VerifyWithPointCompress used to verify src and sign,the pubKey is point compress
// If userID be assigned nil,which  default value is 1234567812345678
func VerifyWithPointCompress(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error) {
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return false, err
	}

	publicKey := decompress(pubKeyBytes)
	return Verify(publicKey, userID, src, sign), nil
}

// VerifyX function is similar with VerifyWithPointCompress,the pubKey is unCompress
func VerifyX(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error) {
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
