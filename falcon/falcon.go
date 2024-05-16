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
	Dilithium2PublicKey Falcon512PublicKey
	Secret              oqs.Signature
	publicKeyGenerated  bool
}

func (priv Falcon512PrivateKey) Public() crypto.PublicKey {
	if !priv.publicKeyGenerated {
		sig := oqs.Signature{}
		if err := sig.Init("Falcon512", nil); err != nil {
			return nil
		}
		publicKey, err := sig.GenerateKeyPair()
		priv.Secret = sig
		//print("Secreto" + string(priv.Secret))
		if err != nil {

			return nil
		}

		priv.Dilithium2PublicKey.Value = publicKey
		priv.publicKeyGenerated = true
	}
	return priv.Dilithium2PublicKey
}

func GenerateFalcon512KeyPair() *Falcon512PrivateKey {
	sig := oqs.Signature{}
	sig.Init("Falcon512", nil)

	key := Falcon512PrivateKey{}

	publicKey, _ := sig.GenerateKeyPair()
	key.Dilithium2PublicKey.Value = publicKey
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

// Falcon 512
type Falcon1024PublicKey struct {
	Value []byte
}

type Falcon1024PrivateKey struct {
	Dilithium2PublicKey Falcon512PublicKey
	Secret              oqs.Signature
	publicKeyGenerated  bool
}

func (priv Falcon1024PrivateKey) Public() crypto.PublicKey {
	if !priv.publicKeyGenerated {
		sig := oqs.Signature{}
		if err := sig.Init("Falcon1024", nil); err != nil {
			return nil
		}
		publicKey, err := sig.GenerateKeyPair()
		priv.Secret = sig
		//print("Secreto" + string(priv.Secret))
		if err != nil {

			return nil
		}

		priv.Dilithium2PublicKey.Value = publicKey
		priv.publicKeyGenerated = true
	}
	return priv.Dilithium2PublicKey
}

func GenerateDilithium2KeyPair() *Falcon1024PrivateKey {
	sig := oqs.Signature{}
	sig.Init("Falcon1024", nil)

	key := Falcon1024PrivateKey{}

	publicKey, _ := sig.GenerateKeyPair()
	key.Dilithium2PublicKey.Value = publicKey
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
