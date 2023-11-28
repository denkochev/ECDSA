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

// return Public key as hex string
func (publicKey *ElipticPoint) ToHex() string {
	x, y := publicKey.X.Text(16), publicKey.Y.Text(16)

	for len(x) < 64 {
		x = "0" + x
	}

	for len(y) < 64 {
		y = "0" + y
	}

	return x + y
}

// set Public key from hex string
func (publicKey *ElipticPoint) SetFromHex(hex string) {
	publicKey.X, publicKey.Y = big.NewInt(0), big.NewInt(0)

	x := hex[:64]
	y := hex[64:]

	publicKey.X.SetString(x, 16)
	publicKey.Y.SetString(y, 16)
}

// set signature from hex numbers
func (signature *Signature) SetFromHex(hex string) {
	signature.r, signature.s = big.NewInt(0), big.NewInt(0)

	r := hex[:64]
	s := hex[64:]

	signature.r.SetString(r, 16)
	signature.s.SetString(s, 16)
}

// return signature in hex format
func (signature *Signature) ToHex() string {
	r, s := signature.r.Text(16), signature.s.Text(16)

	for len(r) < 64 {
		r = "0" + r
	}

	for len(s) < 64 {
		s = "0" + s
	}

	return r + s
}

// print signature in hex format
func (signature *Signature) PrintHex() {
	r, s := signature.r.Text(16), signature.s.Text(16)

	for len(r) < 64 {
		r = "0" + r
	}

	for len(s) < 64 {
		s = "0" + s
	}

	fmt.Println(r + s)
}

// print numbers
func (signature *Signature) Print() {
	r, s := signature.r.Text(10), signature.s.Text(10)
	fmt.Println(r)
	fmt.Println(s)
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

/*
m - message to sig,
d - private key
*/
func SIG(m, d []byte) Signature {
	n := btcec.Params().N // n param from secp256k1 curve
	r := big.NewInt(0)
	var k *secp256k1.PrivateKey
	for r.Cmp(big.NewInt(0)) == 0 {
		k, _ = btcec.NewPrivateKey() // random ∈ [1, n-1]
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
	K.ModInverse(K, n) // k^-1

	s := big.NewInt(0)
	s.Mul(K, e) // k^-1 * (e + dr)
	s.Mod(s, n) // mod n

	signature := Signature{}
	signature.r = r
	signature.s = s

	return signature
}

func Verify(m []byte, publicKey ElipticPoint, signature Signature) bool {
	r, s := signature.r, signature.s

	n := btcec.Params().N
	n_minus_1 := big.NewInt(0)
	n_minus_1.Sub(n, big.NewInt(1)) // n - 1

	r_compare_1, b_compare_1 := r.Cmp(big.NewInt(1)), s.Cmp(big.NewInt(1))
	r_compare_n_minus1, b_compare_n_minus1 := r.Cmp(n_minus_1), s.Cmp(n_minus_1)

	// check if  (r,s) ∈ [1, n-1]
	if r_compare_1 == -1 || b_compare_1 == -1 || r_compare_n_minus1 == 1 || b_compare_n_minus1 == 1 {
		return false
	}

	h := sha256.New()
	h.Write(m)
	e := big.NewInt(0)
	e.SetBytes(h.Sum(nil)) // e = Hash(msg) (in bigInt format)

	w := big.NewInt(0)
	w.ModInverse(s, n) // w = s^-1 mod n

	ew := big.NewInt(0)
	ew.Mul(e, w) // ew = e * w
	u1 := big.NewInt(0)
	u1.Mod(ew, n) // u1 = ew mod n

	rw := big.NewInt(0)
	rw.Mul(r, w) // rw = r * w
	u2 := big.NewInt(0)
	u2.Mod(rw, n) // u2 = rw mod n

	// get G basic point
	G := ElipticPoint{}
	G.X = btcec.S256().Gx
	G.Y = btcec.S256().Gy

	u1G := ScalarMult(G, u1)
	u2Q := ScalarMult(publicKey, u2) // publicKey = Q

	X := AddElipticPoints(u1G, u2Q)

	v := big.NewInt(0)
	v.Mod(X.X, n)

	res := v.Cmp(r)
	// fmt.Println(v)
	// fmt.Println(r)

	return res == 0
}

/*
helpers
*/

func ScalarMult(point ElipticPoint, k *big.Int) ElipticPoint {
	result := ElipticPoint{}
	result.X, result.Y = btcec.S256().ScalarMult(point.X, point.Y, k.Bytes())
	return result
}

// point A + point B = Point C
func AddElipticPoints(a, b ElipticPoint) ElipticPoint {
	resultPoint := ElipticPoint{}

	resultPoint.X, resultPoint.Y = btcec.S256().Add(a.X, a.Y, b.X, b.Y)

	return resultPoint
}
