package falcon

import (
	"crypto"
	"io"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Falcon 512
type Falcon512PublicKey struct {
	Value []byte
}

type Falcon512PrivateKey struct {
	Falcon512PublicKey Falcon512PublicKey
	Secret             oqs.Signature
	publicKeyGenerated bool
}

func (priv Falcon512PrivateKey) Public() crypto.PublicKey {
	if !priv.publicKeyGenerated {
		sig := oqs.Signature{}
		if err := sig.Init("Falcon-512", nil); err != nil {
			return nil
		}
		publicKey, err := sig.GenerateKeyPair()
		priv.Secret = sig
		//print("Secreto" + string(priv.Secret))
		if err != nil {

			return nil
		}

		priv.Falcon512PublicKey.Value = publicKey
		priv.publicKeyGenerated = true
	}
	return priv.Falcon512PublicKey
}

func GenerateFalcon512KeyPair() *Falcon512PrivateKey {
	sig := oqs.Signature{}
	sig.Init("Falcon-512", nil)

	key := Falcon512PrivateKey{}

	publicKey, _ := sig.GenerateKeyPair()
	key.Falcon512PublicKey.Value = publicKey
	key.Secret = sig
	key.publicKeyGenerated = true

	return &key
}

func (priv Falcon512PrivateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	signature, err := priv.Secret.Sign(digest)
	if err != nil {
		print("ERROR FIRMANDO")
		return nil, err
	}
	return signature, nil
}

func (pub Falcon512PublicKey) Verify(message []byte, signature []byte) (bool, error) {
	sig := oqs.Signature{}
	if err := sig.Init("Falcon-512", nil); err != nil {
		return false, err
	}
	defer sig.Clean()

	valid, err := sig.Verify(message, signature, pub.Value)
	if err != nil {
		return false, err
	}
	return valid, nil
}

// Falcon 1024
type Falcon1024PublicKey struct {
	Value []byte
}

type Falcon1024PrivateKey struct {
	Falcon1024PublicKey Falcon512PublicKey
	Secret              oqs.Signature
	publicKeyGenerated  bool
}

func (priv Falcon1024PrivateKey) Public() crypto.PublicKey {
	if !priv.publicKeyGenerated {
		sig := oqs.Signature{}
		if err := sig.Init("Falcon-1024", nil); err != nil {
			return nil
		}
		publicKey, err := sig.GenerateKeyPair()
		priv.Secret = sig
		//print("Secreto" + string(priv.Secret))
		if err != nil {

			return nil
		}

		priv.Falcon1024PublicKey.Value = publicKey
		priv.publicKeyGenerated = true
	}
	return priv.Falcon1024PublicKey
}

func GenerateFalcon1024KeyPair() *Falcon1024PrivateKey {
	sig := oqs.Signature{}
	sig.Init("Falcon-1024", nil)

	key := Falcon1024PrivateKey{}

	publicKey, _ := sig.GenerateKeyPair()
	key.Falcon1024PublicKey.Value = publicKey
	key.Secret = sig
	key.publicKeyGenerated = true

	return &key
}

func (priv Falcon1024PrivateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	signature, err := priv.Secret.Sign(digest)
	if err != nil {
		print("ERROR FIRMANDO")
		return nil, err
	}
	return signature, nil
}

func (pub Falcon1024PublicKey) Verify(message []byte, signature []byte) (bool, error) {
	sig := oqs.Signature{}
	if err := sig.Init("Falcon-1024", nil); err != nil {
		return false, err
	}
	defer sig.Clean()

	valid, err := sig.Verify(message, signature, pub.Value)
	if err != nil {
		return false, err
	}
	return valid, nil
}
