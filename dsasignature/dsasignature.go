package dsasignature

import (
	"crypto/dsa"
	"crypto/rand"
	"hash"
	"io"
	"math/big"

	"github.com/lann/sts"
)

var _ sts.Signature = &DSASignature{}

type DSASignature struct {
	Rand io.Reader

	hashFunc      func() hash.Hash
	privateKey    *dsa.PrivateKey
	peerPublicKey *dsa.PublicKey

	byteSize int
	hashSize int
}

func New(
	hashFunc func() hash.Hash,
	privateKey *dsa.PrivateKey,
	peerPublicKey *dsa.PublicKey,
) *DSASignature {
	byteSize := (privateKey.P.BitLen() + 7) >> 3 // ceil(bitlen / 8)
	hashSize := (privateKey.Q.BitLen() + 7) >> 3
	if hashFunc().Size() < hashSize {
		panic("DSASignature hash size must be at least as large as Q size")
	}
	return &DSASignature{
		Rand:          rand.Reader,
		hashFunc:      hashFunc,
		privateKey:    privateKey,
		peerPublicKey: peerPublicKey,
		byteSize:      byteSize,
		hashSize:      hashSize,
	}
}

func (s *DSASignature) toBytes(n *big.Int) []byte {
	bytes := make([]byte, s.byteSize)
	nBytes := n.Bytes()
	pad := len(bytes) - len(nBytes)
	copy(bytes[pad:], nBytes)
	return bytes
}

func (s *DSASignature) Sign(data []byte) ([]byte, error) {
	hash := s.hashFunc().Sum(data)[:s.hashSize]
	a, b, err := dsa.Sign(s.Rand, s.privateKey, hash)
	if err != nil {
		return nil, err
	}
	return append(s.toBytes(a), s.toBytes(b)...), nil
}

func (s *DSASignature) Verify(data, signature []byte) (ok bool) {
	hash := s.hashFunc().Sum(data)[:s.hashSize]
	a := new(big.Int).SetBytes(signature[:s.byteSize])
	b := new(big.Int).SetBytes(signature[s.byteSize:])
	return dsa.Verify(s.peerPublicKey, hash, a, b)
}

func (s *DSASignature) SignatureSize() int {
	return s.byteSize * 2 // signature is 2 elements
}
