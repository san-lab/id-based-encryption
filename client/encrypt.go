package client

import (
	"crypto/rand"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/san-lab/id-based-encryption/common"
)

type BLSCiphertext struct {
	U *bls12381.G1Affine
	V []byte
}

var PublicMasterKey common.PublicKey

// max msg length 256 bytes
func Encrypt(id, plaintext []byte) (BLSCiphertext, error) {
	// From randomness r, calculate U = rP
	r := make([]byte, common.SizeFr)
	_, err := io.ReadFull(rand.Reader, r)
	if err != nil {
		return BLSCiphertext{}, err
	}
	rP := new(bls12381.G1Affine)
	common.ScalarMultBaseG1(rP, new(big.Int).SetBytes(r))

	// Calculate V = m xor H3(e(sP, idH)^r)
	idH, err := common.H2(id)
	if err != nil {
		return BLSCiphertext{}, err
	}
	pair, err := common.PairG1G2(common.PublicMasterKey.A, idH) // TODO: should get tpkg public key from somewhere else
	if err != nil {
		return BLSCiphertext{}, err
	}
	pair_r := new(bls12381.E12)
	pair_r.Exp(pair, new(big.Int).SetBytes(r))
	pair_r_H := common.H3(*pair_r)
	m_xor_pair_r_H, err := common.XOR(common.PAD(plaintext, len(pair_r_H)), pair_r_H) // TODO: move padding to somewhere more visible
	if err != nil {
		return BLSCiphertext{}, err
	}
	return BLSCiphertext{U: rP, V: m_xor_pair_r_H}, nil
}
