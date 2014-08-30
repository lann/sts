package ecdsasignature

import (
	"crypto/ecdsa"
	"crypto/rand"
	"hash"
	"io"
	"math/big"

	"github.com/lann/sts"
)

var _ sts.Signature = &ECDSASignature{}

type ECDSASignature struct {
	Rand io.Reader

	hashFunc      func() hash.Hash
	privateKey    *ecdsa.PrivateKey
	peerPublicKey *ecdsa.PublicKey

	byteSize int
	hashSize int
}

func New(
	hashFunc func() hash.Hash,
	privateKey *ecdsa.PrivateKey,
	peerPublicKey *ecdsa.PublicKey,
) *ECDSASignature {
	byteSize := (privateKey.Params().N.BitLen() + 7) >> 3 // ceil(bitlen / 8)
	return &ECDSASignature{
		Rand:          rand.Reader,
		hashFunc:      hashFunc,
		privateKey:    privateKey,
		peerPublicKey: peerPublicKey,
		byteSize:      byteSize,
	}
}

func (s *ECDSASignature) toBytes(n *big.Int) []byte {
	bytes := make([]byte, s.byteSize)
	nBytes := n.Bytes()
	pad := len(bytes) - len(nBytes)
	copy(bytes[pad:], nBytes)
	return bytes
}

func (s *ECDSASignature) Sign(data []byte) ([]byte, error) {
	hash := s.hashFunc().Sum(data)
	a, b, err := ecdsa.Sign(s.Rand, s.privateKey, hash)
	if err != nil {
		return nil, err
	}
	return append(s.toBytes(a), s.toBytes(b)...), nil
}

func (s *ECDSASignature) Verify(data, signature []byte) (ok bool) {
	hash := s.hashFunc().Sum(data)
	a := new(big.Int).SetBytes(signature[:s.byteSize])
	b := new(big.Int).SetBytes(signature[s.byteSize:])
	return ecdsa.Verify(s.peerPublicKey, hash, a, b)
}

func (s *ECDSASignature) SignatureSize() int {
	return s.byteSize * 2 // signature is 2 elements
}
