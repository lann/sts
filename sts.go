package sts

import (
	"fmt"
	"math/big"
)

// STS is an implementation of the Station-to-Station protocol.
//
// STS authenticates two stations (A and B) to one another and results in a
// random shared key known only to the stations.
type STS interface {
	// GenerateM1 is step 1 of the STS.
	//
	// A sends m1 to B and keeps x.
	GenerateM1() (m1 []byte, x *big.Int, err error)

	// GenerateM2 is step 2 of the STS.
	//
	// B receives m1 and uses it to generate m2 and key.
	// B sends m2 to A and keeps key.
	GenerateM2(m1 []byte) (m2, key []byte, err error)

	// GenerateM3 is step 3 of the STS.
	//
	// A receives m2, verifies it with x, and uses it to generate m3 and key.
	// A sends m3 to B and keeps key.
	//
	// GenerateM3 returns VerificationFailed if verification of m2 fails.
	GenerateM3(m2 []byte, x *big.Int) (m3, key []byte, err error)

	// Verify is step 4 of the STS.
	//
	// B receives m3 and uses m1, m2, and key to verify it.
	//
	// Verify returns VerificationFailed if the verification fails.
	Verify(m1, m2, m3, key []byte) error
}

// FixedSizeSTS is an STS with fixed-size messages.
type FixedSizeSTS interface {
	STS
	M1Size() int
	M2Size() int
	M3Size() int
}

var VerificationFailed = fmt.Errorf("Message verification failed")

// Field implementations represent mathematical finite fields appropriate for
// use with Diffie-Hellman key exchange along with a fixed-width byte
// representation of elements in the field.
type Field interface {
	// Elem returns the byte representation of the n'th element of the field
	// (e.g. g^n mod p)
	Elem(n *big.Int) (elem []byte)

	// ScalarMult returns the byte representation of the result of multiplying
	// the given element by the given scalar (e.g. (g^a)^b mod p)
	ScalarMult(a []byte, b *big.Int) (elem []byte)

	// Order returns the number of elements in the field.
	Order() (N *big.Int)

	// ElemSize returns the size of the byte representation of a field element.
	ElemByteSize() int
}

// Signature can be implemented by digital signatures like DSA.
type Signature interface {
	// Sign returns the byte representation of a signature for the given data.
	Sign(data []byte) (signature []byte, err error)

	// Verify checks the validity of the given signature and data.
	Verify(data, signature []byte) (ok bool)

	// SignatureSize returns the byte size of a signature.
	SignatureSize() int
}
