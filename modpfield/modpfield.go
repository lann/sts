package modpfield

import (
	"fmt"
	"math/big"

	"github.com/lann/sts"
)

type modpField struct {
	G *big.Int
	P *big.Int
	byteSize int
}

var HexDecodeFailed = fmt.Errorf("Failed to set big.Int from hex string")

func New(g, p *big.Int) sts.Field {
	byteSize := (p.BitLen() + 7) >> 3 // ceil(bitlen / 8)
	return &modpField{G: g, P: p, byteSize: byteSize}
}

func NewHex(gStr, pStr string) (sts.Field, error) {
	g, ok := new(big.Int).SetString(gStr, 16)
	if !ok {
		return nil, HexDecodeFailed
	}
	p, ok := new(big.Int).SetString(pStr, 16)
	if !ok {
		return nil, HexDecodeFailed
	}
	return New(g, p), nil
}

func NewHexPanic(gStr, pStr string) sts.Field {
	f, err := NewHex(gStr, pStr)
	if err != nil {
		panic(err)
	}
	return f
}

func (f *modpField) bytes(elem *big.Int) []byte {
	bytes := make([]byte, f.byteSize)
	elemBytes := elem.Bytes()
	pad := f.byteSize - len(elemBytes)
	copy(bytes[pad:], elemBytes)
	return bytes
}

func (f *modpField) Elem(n *big.Int) []byte {
	return f.bytes(new(big.Int).Exp(f.G, n, f.P))
}

func (f *modpField) ScalarMult(a []byte, b *big.Int) (elem []byte) {
	base := new(big.Int).SetBytes(a)
	return f.bytes(base.Exp(base, b, f.P))
}

func (f *modpField) Order() (N *big.Int) {
	return f.P
}

func (f *modpField) ElemByteSize() int {
	return f.byteSize
}
