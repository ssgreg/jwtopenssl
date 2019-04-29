package jwtopenssl

import (
	"github.com/ssgreg/jwt-go"
	"github.com/ssgreg/openssl"
)

type signingMethodRSA struct {
	Name   string
	Method openssl.Method
}

// Specific instances for RS256 and company,
var (
	SigningMethodRS256 jwt.SigningMethod
	SigningMethodRS512 jwt.SigningMethod
)

func init() {
	// RS256
	SigningMethodRS256 = &signingMethodRSA{"RS256", openssl.SHA256_Method}
	jwt.RegisterSigningMethod(SigningMethodRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS256
	})

	// RS512
	SigningMethodRS512 = &signingMethodRSA{"RS512", openssl.SHA512_Method}
	jwt.RegisterSigningMethod(SigningMethodRS512.Alg(), func() jwt.SigningMethod {
		return SigningMethodRS512
	})
}

func (m *signingMethodRSA) Alg() string {
	return m.Name
}

// Implements the Verify method from SigningMethod.
// For this signing method, must be an openssl.PublicKey structure.
func (m *signingMethodRSA) Verify(signingString, signatureStr string, publicKey interface{}) error {
	key, ok := publicKey.(openssl.PublicKey)
	if !ok {
		return jwt.ErrInvalidKey
	}
	signature, err := jwt.DecodeSegment(signatureStr)
	if err != nil {
		return err
	}

	return key.VerifyPKCS1v15(m.Method, []byte(signingString), signature)
}

// Implements the Sign method from SigningMethod.
// For this signing method, must be an openssl.PrivateKey structure.
func (m *signingMethodRSA) Sign(signingString string, privateKey interface{}) (string, error) {
	key, ok := privateKey.(openssl.PrivateKey)
	if !ok {
		return "", jwt.ErrInvalidKey
	}
	signature, err := key.SignPKCS1v15(m.Method, []byte(signingString))
	if err != nil {
		return "", err
	}

	return jwt.EncodeSegment(signature), nil
}
