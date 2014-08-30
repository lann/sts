package ellipticfield

import (
	"crypto/elliptic"
	"math/big"

	"github.com/lann/sts"
)

type ellipticField struct {
	elliptic.Curve
}

func New(curve elliptic.Curve) sts.Field {
	return &ellipticField{curve}
}

func (f ellipticField) toBytes(x, y *big.Int) []byte {
	return elliptic.Marshal(f.Curve, x, y)[1:] // Strip type byte
}

func (f ellipticField) fromBytes(data []byte) (x, y *big.Int) {
	return elliptic.Unmarshal(f.Curve, append([]byte{4}, data...))
}

func (f ellipticField) Elem(n *big.Int) []byte {
	return f.toBytes(f.ScalarBaseMult(n.Bytes()))
}

func (f ellipticField) ScalarMult(a []byte, b *big.Int) (elem []byte) {
	x, y := f.fromBytes(a)
	return f.toBytes(f.Curve.ScalarMult(x, y, b.Bytes()))
}

func (f ellipticField) Order() (N *big.Int) {
	return f.Params().N
}

func (f ellipticField) ElemByteSize() int {
	byteSize := (f.Params().BitSize + 7) >> 3 // ceil(bitSize / 8)
	return byteSize * 2 // X and Y coords
}
