package cipherutil

import (
	"crypto/cipher"

	"github.com/lann/sts"
)

type BlockFunc func(key []byte) (cipher.Block, error)

func WrapBlock(keySize int, blockFunc BlockFunc) sts.SizedCipher {
	streamFunc := func(key []byte) (cipher.Stream, error) {
		block, err := blockFunc(key)
		if err != nil {
			return nil, err
		}
		iv := make([]byte, block.BlockSize())
		return cipher.NewCTR(block, iv), nil
	}
	return WrapStream(keySize, streamFunc)
}
