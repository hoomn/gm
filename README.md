# Generate public key and private key
// GeneratePointCompressKeyX used to product publicKey and privateKey.   
// The publicKey is ponit compressed    
func GeneratePointCompressKeyX() (pubKey string, priKey string, err error)    

# Generate public key and private key
// GenerateKeyX used to product publicKey and privateKey    
func GenerateKeyX() (pubKey string, priKey string, err error)

# sm2 sign
// SignX used to sign src,priKey is hex string.   
// If userID be assigned nil,which  will be use default value    
func SignX(priKey string, userID []byte, src []byte) ([]byte, error) 

# sm2 verify
// VerifyWithPointCompress used to verify src and sign.the pubKey is point compressed      
// If userID be assigned nil,which  will be use default value    
func VerifyWithPointCompress(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error)

# sm2 verify
// VerifyX function is similar with VerifyWithPointCompress,the pubKey is unCompress    
func VerifyX(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error)