package cipherutil

import (
	"crypto/cipher"

	"github.com/lann/sts"
)

type streamWrapper struct {
	keySize int
	streamFunc StreamFunc
}

type StreamFunc func(key []byte) (cipher.Stream, error)

func WrapStream(keySize int, streamFunc StreamFunc) sts.SizedCipher {
	return &streamWrapper{keySize: keySize, streamFunc: streamFunc}
}

func (w *streamWrapper) crypt(key, src []byte) ([]byte, error) {
	stream, err := w.streamFunc(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(src))
	stream.XORKeyStream(dst, src)
	return dst, nil
}

func (w *streamWrapper) Encrypt(key, data []byte) ([]byte, error) {
	return w.crypt(key, data)
}

func (w *streamWrapper) Decrypt(key, data []byte) ([]byte, error) {
	return w.crypt(key, data)
}

func (w *streamWrapper) KeySize() int {
	return w.keySize
}

func (w *streamWrapper) CipherSize(plainSize int) int {
	return plainSize
}
