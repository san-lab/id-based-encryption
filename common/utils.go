package common

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const SizeFr = fr.Bytes

var order = fr.Modulus()
var one = new(big.Int).SetInt64(1)

type PublicKey struct {
	A bls12381.G1Affine `json:"a"`
}

type PrivateKey struct {
	PublicKey PublicKey    `json:"publickey"`
	Scalar    [SizeFr]byte `json:"scalar"`
}

var PublicMasterKey PublicKey

func (pub PublicKey) Marshal() ([]byte, error) {
	pubM := pub.A.Marshal()
	return pubM, nil
}

func (pub *PublicKey) Unmarshal(data []byte) error {
	A := new(bls12381.G1Affine)
	err := A.Unmarshal(data)
	if err != nil {
		return err
	}
	pub.A = *A
	return nil
}

// privKey, err := ecdsa.GenerateKey(seed)
// Cannot use the above line because ecdsa.PrivateKey has inaccesible scalar

func GenerateKeysG1() (*PrivateKey, error) {
	seed := rand.Reader // correct initialization?¿
	k, err := randFieldElement(seed)
	if err != nil {
		return nil, err

	}
	_, _, g1, _ := bls12381.Generators()

	privKey := new(PrivateKey)
	k.FillBytes(privKey.Scalar[:SizeFr])
	privKey.PublicKey.A.ScalarMultiplication(&g1, k)
	return privKey, nil
}

func randFieldElement(rand io.Reader) (k *big.Int, err error) {
	b := make([]byte, fr.Bits/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(order, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func H1(msg []byte) (bls12381.G1Affine, error) {
	q, err := bls12381.HashToG1(msg, nil) // See what dst is
	return q, err
}

func H2(msg []byte) (bls12381.G2Affine, error) {
	q, err := bls12381.HashToG2(msg, nil) // See what dst is
	return q, err
}

func H3(msg bls12381.E12) []byte {
	h := sha256.New()
	h.Write(msg.Marshal())
	return h.Sum(nil)
}

func ScalarMultBaseG1(p *bls12381.G1Affine, s *big.Int) {
	p.ScalarMultiplicationBase(s)
}

/*
func ScalarMultG1(p *bls12381.G1Affine, a *bls12381.G1Affine, s *big.Int) {
	p.ScalarMultiplication(a, s)
}
*/

func ScalarMultG2(p *bls12381.G2Affine, a *bls12381.G2Affine, s *big.Int) {
	p.ScalarMultiplication(a, s)
}

func PairG1G2(G1Point bls12381.G1Affine, G2Point bls12381.G2Affine) (bls12381.E12, error) {
	return bls12381.Pair([]bls12381.G1Affine{G1Point}, []bls12381.G2Affine{G2Point})
}

func XOR(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("xor: byte slices of different length")
	}
	result := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

func PAD(a []byte, n int) []byte {
	if n <= len(a) {
		return a
	}
	zeroes := make([]byte, n-len(a))
	padded := append(zeroes, a...)
	return padded
}
