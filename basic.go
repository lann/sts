package sts

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"io"

	"code.google.com/p/go.crypto/hkdf"
)

var (
	m2Info = []byte("STS-M2")
	m3Info = []byte("STS-M3")
)

type KDFFunc func(keySize int, secret, info []byte) ([]byte, error)

func DefaultKDFFunc(keySize int, secret, info []byte) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := hkdf.New(sha256.New, secret, nil, info).Read(key)
	return key, err
}

// Cipher is implemented by a symmetric-key algorithm.
type Cipher interface {
	// Encrypt takes a key and plain text data and returns the encrypted cipher text.
	Encrypt(key, data []byte) ([]byte, error)

	// Decrypt takes a key and cipher text data and returns the decrypted plain text.
	Decrypt(key, data []byte) ([]byte, error)

	// KeySize returns cipher's key length in bytes.
	KeySize() int
}

type BasicSTS struct {
	Rand io.Reader
	KDFFunc KDFFunc

	fld  Field
	sig  Signature
	ciph Cipher
}

func NewBasicSTS(fld Field, sig Signature, ciph Cipher) *BasicSTS {
	return &BasicSTS{
		Rand: rand.Reader,
		KDFFunc: DefaultKDFFunc,
		fld: fld,
		sig: sig,
		ciph: ciph,
	}
}

func (b *BasicSTS) GenerateM1() (m1 []byte, x *big.Int, err error) {
	x, err = rand.Int(b.Rand, b.fld.Order())
	if err != nil {
		return
	}
	m1 = b.fld.Elem(x)
	return
}

func (b *BasicSTS) GenerateM2(m1 []byte) (m2, key []byte, err error) {
	y, err := rand.Int(b.Rand, b.fld.Order())
	if err != nil {
		return
	}
	gy := b.fld.Elem(y)

	gx := m1
	key = b.fld.ScalarMult(gx, y)

	proof, err := b.genProof(key, m2Info, gy, gx)
	if err != nil {
		key = nil
	}
	m2 = append(gy, proof...)
	return
}

func (b *BasicSTS) GenerateM3(m2 []byte, x *big.Int) (m3, key []byte, err error) {
	gy := m2[:b.fld.ElemByteSize()]
	key = b.fld.ScalarMult(gy, x)

	proof := m2[b.fld.ElemByteSize():]
	gx := b.fld.Elem(x)
	err = b.verifyProof(proof, key, m2Info, gy, gx)
	if err != nil {
		key = nil
		return
	}

	m3, err = b.genProof(key, m3Info, gx, gy)
	if err != nil {
		key = nil
	}
	return
}

func (b *BasicSTS) Verify(m1, m2, m3, key []byte) error {
	gx := m1
	gy := m2[:b.fld.ElemByteSize()]
	return b.verifyProof(m3, key, m3Info, gx, gy)
}

func (b *BasicSTS) genProof(key, info, d1, d2 []byte) ([]byte, error) {
	sig, err := b.sig.Sign(append(d1, d2...))
	if err != nil {
		return nil, err
	}
	encKey, err := b.KDFFunc(b.ciph.KeySize(), key, append(info, "-PROOF"...))
	if err != nil {
		return nil, err
	}
	return b.ciph.Encrypt(encKey, sig)
}

func (b *BasicSTS) verifyProof(proof, key, info, d1, d2 []byte) error {
	encKey, err := b.KDFFunc(b.ciph.KeySize(), key, append(info, "-PROOF"...))
	if err != nil {
		return err
	}
	sig, err := b.ciph.Decrypt(encKey, proof)
	if err != nil {
		return err
	}
	if !b.sig.Verify(append(d1, d2...), sig) {
		return VerificationFailed
	}
	return nil
}
