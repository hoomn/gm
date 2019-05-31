# // GenerateSm2Key used to product publicKey and privateKey.
# // The publicKey is ponit compressed
# func GenerateSm2Key() (pubKey string, priKey string, err error) 

#// SignWithSm2 used to sign src,priKey is hex string.
#// If userID be assigned nil,which  will be assigned default value
#func SignWithSm2(priKey string, userID []byte, src []byte) ([]byte, error) 

#// VerifyWithSm2 used to verify src and sign.
#// If userID be assigned nil,which  will be assigned default value
#func VerifyWithSm2(pubKey string, userID []byte, src []byte, sign []byte) (pass bool, err error)