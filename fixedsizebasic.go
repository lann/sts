package sts

// SizedCipher is implemented by a Cipher with predictable ciphertext sizes.
type SizedCipher interface {
	Cipher

	// CipherSize returns the byte length of the cipher text that would be
	// produced by encrypting a plain text of the given length.
	CipherSize(plainSize int) int
}

type fixedSizeBasicSTS struct {
	*BasicSTS
	sizedCiph SizedCipher
}

func NewFixedSizeBasicSTS(fld Field, sig Signature, sizedCiph SizedCipher) FixedSizeSTS {
	return &fixedSizeBasicSTS{
		BasicSTS: NewBasicSTS(fld, sig, sizedCiph),
		sizedCiph: sizedCiph,
	}
}

func (b *fixedSizeBasicSTS) M1Size() int {
	return b.fld.ElemByteSize()
}

func (b *fixedSizeBasicSTS) M2Size() int {
	return b.fld.ElemByteSize() + b.sizedCiph.CipherSize(b.sig.SignatureSize())
}

func (b *fixedSizeBasicSTS) M3Size() int {
	return b.sizedCiph.CipherSize(b.sig.SignatureSize())
}
