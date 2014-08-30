package curve25519field

import (
	"math/big"

	"code.google.com/p/go.crypto/curve25519"

	"github.com/lann/sts"
)

// "...allow all 32-byte strings as Diffie-Hellman public keys."
const byteSize = 32
var order = new(big.Int).Exp(big.NewInt(8), big.NewInt(byteSize), nil)

var Field sts.Field = f{}

type f struct{}

func (f) Elem(n *big.Int) []byte {
	var elem [byteSize]byte
	curve25519.ScalarBaseMult(&elem, intToBytes(n))
	return elem[:]
}

func (f) ScalarMult(a []byte, b *big.Int) []byte {
	var base, elem [byteSize]byte
	copy(base[:], a)
	curve25519.ScalarMult(&elem, intToBytes(b), &base)
	return elem[:]
}

func (f) Order() (N *big.Int) {
	return order
}

func (f) ElemByteSize() int {
	return byteSize
}

// big.Int to little-endian []byte
func intToBytes(n *big.Int)  *[byteSize]byte {
	bytes := new([byteSize]byte)
	nBytes := n.Bytes()
	lastNByte := len(nBytes) - 1
	for i, b := range nBytes {
		bytes[lastNByte - i] = b
	}
	return bytes
}
