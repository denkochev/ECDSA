package ecdsa

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type ElipticPoint struct {
	X *big.Int
	Y *big.Int
}

type Signature struct {
	r *big.Int
	s *big.Int
}

func KeyGen() ([]byte, ElipticPoint) {
	pubKec := ElipticPoint{}

	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		fmt.Println("error in generating private key")
	}
	publicKey := privateKey.PubKey()

	pubKec.X, pubKec.Y = publicKey.X(), publicKey.Y()

	return privateKey.Serialize(), pubKec
}

func SIG(m, d []byte) Signature {
	n := btcec.Params().N // n param from secp256k1 curve
	r := big.NewInt(0)
	var k *secp256k1.PrivateKey
	for r.Cmp(big.NewInt(0)) == 0 {
		k, _ = btcec.NewPrivateKey() // random [1, n-1] scalar
		kG := k.PubKey()             // k * G

		r.Mod(kG.X(), n) // r = x1 mod n, if r == 0 generate new values
	}

	h := sha256.New()
	h.Write(m)
	e := big.NewInt(0)
	e.SetBytes(h.Sum(nil)) // e = Hash(msg) (in bigInt format)

	D := big.NewInt(0)
	D.SetBytes(d) // convert []byte to bigInt

	dR := big.NewInt(0)
	dR.Mul(D, r) // d * r

	e.Add(e, dR) // e + dr

	K := big.NewInt(0)
	K.SetBytes(k.Serialize())

	K = K.Mul(K, e) // k * (e + dr)
	s := big.NewInt(0)
	s.ModInverse(K, n) // k^-1(e + dr) mod n

	signature := Signature{}
	signature.r = r
	signature.s = s

	return signature
}
