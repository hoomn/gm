# 产生公钥和私钥
// GenerateKeyX used to product publicKey and privateKey.   
// The publicKey is ponit compressed    
func GenerateKeyX() (pubKey string, priKey string, err error) 

# sm2签名
// SignX used to sign src,priKey is hex string.   
// If userID be assigned nil,which  will be assigned default value    
func SignX(priKey string, userID []byte, src []byte) ([]byte, error) 

# sm2验签
// VerifyX used to verify src and sign.   
// If userID be assigned nil,which  will be assigned default value    
func VerifyX(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error)