package ed25519signature

import (
	"github.com/agl/ed25519"

	"github.com/lann/sts"
)

const (
	PublicKeySize  = ed25519.PublicKeySize
	PrivateKeySize = ed25519.PrivateKeySize
)

type ed25519signature struct {
	privateKey    *[PrivateKeySize]byte
	peerPublicKey *[PublicKeySize]byte
}

func New(
	privateKey *[PrivateKeySize]byte,
	peerPublicKey *[PublicKeySize]byte,
) sts.Signature {
	return &ed25519signature{
		privateKey: privateKey,
		peerPublicKey: peerPublicKey,
	}
}

func (s *ed25519signature) Sign(data []byte) (signature []byte, err error) {
	return ed25519.Sign(s.privateKey, data)[:], nil
}

func (s *ed25519signature) Verify(data, signature []byte) (ok bool) {
	var sig [ed25519.SignatureSize]byte
	copy(sig[:], signature)
	return ed25519.Verify(s.peerPublicKey, data, &sig)
}

func (s *ed25519signature) SignatureSize() int {
	return ed25519.SignatureSize
}
