# Generate public key and private key,the public key is point compress
// BHGeneratePointCompressKey used to product publicKey and privateKey.   
// The publicKey is ponit compressed    
func BHGeneratePointCompressKey() (pubKey string, priKey string, err error)  

# Generate public key and private key
// BHGenerateKey used to product publicKey and privateKey   
func BHGenerateKey() (pubKey string, priKey string, err error)

# sm2 sign
// BHSign used to sign src,priKey is hex string.return r/s bytes    
// If userID be assigned nil,which will use default value,default value is 1234567812345678  bytes 
func BHSign(priKey string, userID []byte, src []byte) ([]byte, error) 

# sm2 sign with asn1
// BHSignX used to sign src,priKey is hex string.return asn.1 format bytes    
// If userID be assigned nil,which will use default value,default value is 1234567812345678  bytes   
func BHSignX(priKey string, userID []byte, src []byte) ([]byte, error)

# sm2 verify use point compress pubkey
// BHVerifyWithPointCompress used to verify src and sign,the pubKey is point compress,the sign is r/s bytes
// If userID be assigned nil,which will use default value,default value is 1234567812345678  bytes
func BHVerifyWithPointCompress(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error)

# sm2 verify use point compress pubkey,the sign is asn1 format
// BHVerifyWithPointCompressX used to verify src and sign,the pubKey is point compress,the sign is asn.1 format bytes   
// If userID be assigned nil,which will use default value,default value is 1234567812345678  bytes
func BHVerifyWithPointCompressX(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error)

# sm2 verify
// BHVerify function is similar with VerifyWithPointCompress,the pubKey is unCompress,the sign is r/s bytes  
// If userID be assigned nil,which will use default value,default value is 1234567812345678  bytes    
func BHVerify(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error))

# sm2 verify,the sign is asn1 format
// BHVerifyX function is similar with VerifyWithPointCompress,the pubKey is unCompress,the sign is asn.1 format bytes
// If userID be assigned nil,which will use default value,default value is 1234567812345678  bytes    
func BHVerifyX(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error)