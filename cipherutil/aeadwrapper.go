package cipherutil

import (
	"crypto/cipher"
	"crypto/rand"

	"github.com/lann/sts"
)

var AEADWrapperData = []byte("STS-AEADWrapperData")

type aeadWrapper struct {
	keySize int
	aeadFunc AEADFunc
}

type AEADFunc func(key []byte) (cipher.AEAD, error)

func WrapAEAD(keySize int, aeadFunc AEADFunc) sts.Cipher {
	return &aeadWrapper{keySize: keySize, aeadFunc: aeadFunc}
}

func (w *aeadWrapper) Encrypt(key, src []byte) ([]byte, error) {
	aead, err := w.aeadFunc(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, src, AEADWrapperData), nil
}

func (w *aeadWrapper) Decrypt(key, src []byte) ([]byte, error) {
	aead, err := w.aeadFunc(key)
	if err != nil {
		return nil, err
	}

	nonceLen := aead.NonceSize()
	nonce := src[:nonceLen]

	return aead.Open([]byte{}, nonce, src[nonceLen:], AEADWrapperData)
}

func (w *aeadWrapper) KeySize() int {
	return w.keySize
}


type fixedOverheadAEADWrapper struct {
	sts.Cipher
	overhead int
}

func WrapFixedOverheadAEAD(keySize int, aeadFunc AEADFunc) (sts.SizedCipher, error) {
	aead, err := aeadFunc(make([]byte, keySize))
	if err != nil {
		return nil, err
	}
	return &fixedOverheadAEADWrapper{
		Cipher: WrapAEAD(keySize, aeadFunc),
		overhead: aead.NonceSize() + aead.Overhead(),
	}, nil
}

func (w *fixedOverheadAEADWrapper) CipherSize(plainSize int) int {
	return plainSize + w.overhead
}
