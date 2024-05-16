package dilithium

import (
	"crypto"
	"io"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// DILITHIUM2
type Dilithium2PublicKey struct {
	Value []byte
}

type Dilithium2PrivateKey struct {
	Dilithium2PublicKey Dilithium2PublicKey
	Secret              oqs.Signature
	publicKeyGenerated  bool
}

func (priv Dilithium2PrivateKey) Public() crypto.PublicKey {
	if !priv.publicKeyGenerated {
		sig := oqs.Signature{}
		if err := sig.Init("Dilithium2", nil); err != nil {
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

func GenerateDilithium2KeyPair() *Dilithium2PrivateKey {
	sig := oqs.Signature{}
	sig.Init("Dilithium2", nil)

	key := Dilithium2PrivateKey{}

	publicKey, _ := sig.GenerateKeyPair()
	key.Dilithium2PublicKey.Value = publicKey
	key.Secret = sig
	key.publicKeyGenerated = true

	return &key
}

func (priv Dilithium2PrivateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	signature, err := priv.Secret.Sign(digest)
	if err != nil {
		print("ERROR FIRMANDO")
		return nil, err
	}
	return signature, nil
}

// DILITHIUM3
type Dilithium3PublicKey struct {
	Value []byte
}

type Dilithium3PrivateKey struct {
	Dilithium2PublicKey Dilithium2PublicKey
	Secret              oqs.Signature
	publicKeyGenerated  bool
}

func (priv Dilithium3PrivateKey) Public() crypto.PublicKey {
	if !priv.publicKeyGenerated {
		sig := oqs.Signature{}
		if err := sig.Init("Dilithium3", nil); err != nil {
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

func GenerateDilithium3KeyPair() *Dilithium3PrivateKey {
	sig := oqs.Signature{}
	sig.Init("Dilithium3", nil)

	key := Dilithium3PrivateKey{}

	publicKey, _ := sig.GenerateKeyPair()
	key.Dilithium2PublicKey.Value = publicKey
	key.Secret = sig
	key.publicKeyGenerated = true

	return &key
}

func (priv Dilithium3PrivateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	signature, err := priv.Secret.Sign(digest)
	if err != nil {
		print("ERROR FIRMANDO")
		return nil, err
	}
	return signature, nil
}

// DILITHIUM5
type Dilithium5PublicKey struct {
	Value []byte
}

type Dilithium5PrivateKey struct {
	Dilithium2PublicKey Dilithium2PublicKey
	Secret              oqs.Signature
	publicKeyGenerated  bool
}

func (priv Dilithium5PrivateKey) Public() crypto.PublicKey {
	if !priv.publicKeyGenerated {
		sig := oqs.Signature{}
		if err := sig.Init("Dilithium2", nil); err != nil {
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

func GenerateDilithium5KeyPair() *Dilithium5PrivateKey {
	sig := oqs.Signature{}
	sig.Init("Dilithium5", nil)

	key := Dilithium5PrivateKey{}

	publicKey, _ := sig.GenerateKeyPair()
	key.Dilithium2PublicKey.Value = publicKey
	key.Secret = sig
	key.publicKeyGenerated = true

	return &key
}

func (priv Dilithium5PrivateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	signature, err := priv.Secret.Sign(digest)
	if err != nil {
		print("ERROR FIRMANDO")
		return nil, err
	}
	return signature, nil
}
