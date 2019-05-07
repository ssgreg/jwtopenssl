package jwtopenssl

import (
	"errors"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/ssgreg/openssl"
)

type signingMethodHMAC struct {
	Name string
	Hash openssl.EVP_MD
}

// Specific instances for HS256 and company
var (
	SigningMethodHS256  jwt.SigningMethod
	SigningMethodHS384  jwt.SigningMethod
	SigningMethodHS512  jwt.SigningMethod
	ErrSignatureInvalid = errors.New("signature is invalid")
)

func init() {
	// HS256
	SigningMethodHS256 = &signingMethodHMAC{"HS256", openssl.EVP_SHA256}
	jwt.RegisterSigningMethod(SigningMethodHS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodHS256
	})

	// HS384
	SigningMethodHS384 = &signingMethodHMAC{"HS384", openssl.EVP_SHA384}
	jwt.RegisterSigningMethod(SigningMethodHS384.Alg(), func() jwt.SigningMethod {
		return SigningMethodHS384
	})

	// HS512
	SigningMethodHS512 = &signingMethodHMAC{"HS512", openssl.EVP_SHA512}
	jwt.RegisterSigningMethod(SigningMethodHS512.Alg(), func() jwt.SigningMethod {
		return SigningMethodHS512
	})
}

func (m *signingMethodHMAC) Alg() string {
	return m.Name
}

// Verify the signature of HSXXX tokens.  Returns nil if the signature is valid.
func (m *signingMethodHMAC) Verify(signingString, signature string, key interface{}) error {
	// Verify the key is the right type
	keyBytes, ok := key.([]byte)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	// Decode signature, for comparison
	sig, err := jwt.DecodeSegment(signature)
	if err != nil {
		return err
	}

	// This signing method is symmetric, so we validate the signature
	// by reproducing the signature from the signing string and key, then
	// comparing that against the provided signature.
	hasher, err := openssl.NewHMAC(keyBytes, m.Hash)
	if err != nil {
		return err
	}

	hasher.Write([]byte(signingString))

	sum, err := hasher.Final()
	if err != nil {
		return err
	}

	if constantTimeCompare(sig, sum) != 1 {
		return ErrSignatureInvalid
	}

	// No validation errors.  Signature is good.
	return nil
}

// Implements the Sign method from SigningMethod for this signing method.
// Key must be []byte
func (m *signingMethodHMAC) Sign(signingString string, key interface{}) (string, error) {
	if keyBytes, ok := key.([]byte); ok {
		hasher, err := openssl.NewHMAC(keyBytes, m.Hash)
		if err != nil {
			return "", err
		}

		hasher.Write([]byte(signingString))

		sum, err := hasher.Final()
		if err != nil {
			return "", err
		}

		return jwt.EncodeSegment(sum), nil
	}

	return "", jwt.ErrInvalidKeyType
}

// constantTimeCompare returns 1 if the two slices, x and y, have equal contents
// and 0 otherwise. The time taken is a function of the length of the slices and
// is independent of the contents.
func constantTimeCompare(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}

	var v byte
	for i := 0; i < len(x); i++ {
		v |= x[i] ^ y[i]
	}

	return constantTimeByteEq(v, 0)
}

// constantTimeByteEq returns 1 if x == y and 0 otherwise.
func constantTimeByteEq(x, y uint8) int {
	return int((uint32(x^y) - 1) >> 31)
}
