package example

import (
	"crypto/cipher"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rc4"
	"crypto/sha256"

	"code.google.com/p/go.crypto/sha3"
	"code.google.com/p/go.crypto/twofish"
	"github.com/codahale/chacha20poly1305"

	"github.com/lann/sts"
	"github.com/lann/sts/cipherutil"
	"github.com/lann/sts/curve25519field"
	"github.com/lann/sts/dsasignature"
	"github.com/lann/sts/ecdsasignature"
	"github.com/lann/sts/ed25519signature"
	"github.com/lann/sts/ellipticfield"
	"github.com/lann/sts/modpfield/rfc3526"
)

func NewGroup2048DSASHA256RC4STS(
	privateKey *dsa.PrivateKey,
	peerPublicKey *dsa.PublicKey,
) sts.FixedSizeSTS {
	streamFunc := func(k []byte) (cipher.Stream, error) { return rc4.NewCipher(k) }
	return sts.NewFixedSizeBasicSTS(
		rfc3526.Group2048(),
		dsasignature.New(sha256.New, privateKey, peerPublicKey),
		cipherutil.WrapStream(16, streamFunc),
	)
}

func NewP256ECDSAKeccak256TwofishGCMSTS(
	privateKey *ecdsa.PrivateKey,
	peerPublicKey *ecdsa.PublicKey,
) sts.FixedSizeSTS {
	blockFunc := func(k []byte) (cipher.Block, error) { return twofish.NewCipher(k) }
	return sts.NewFixedSizeBasicSTS(
		ellipticfield.New(elliptic.P256()),
		ecdsasignature.New(sha3.NewKeccak256, privateKey, peerPublicKey),
		cipherutil.WrapBlock(16, blockFunc),
	)
}

func NewCurve25519Ed25519ChaCha20Poly1305STS(
	privateKey *[ed25519signature.PrivateKeySize]byte,
	peerPublicKey *[ed25519signature.PublicKeySize]byte,
) (sts.FixedSizeSTS, error) {
	signature := ed25519signature.New(privateKey, peerPublicKey)
	ciph, err := cipherutil.WrapFixedOverheadAEAD(
		chacha20poly1305.KeySize,
		chacha20poly1305.NewChaCha20Poly1305)
	if err != nil {
		return nil, err
	}
	return sts.NewFixedSizeBasicSTS(curve25519field.Field, signature, ciph), nil
}
