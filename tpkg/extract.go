package tpkg

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/san-lab/id-based-encryption/common"
)

// Something to prove your identity
type SoulToken interface {
	ItsMe(interface{}) bool
}

// Only the owner of the id should be able to call it
func Extract(id []byte, soul SoulToken) (*bls12381.G2Affine, error) {
	_ = soul
	// Calculate sidH = s * H2(id)
	idH, err := common.H2(id)
	if err != nil {
		return nil, err
	}
	userPrivKey := new(bls12381.G2Affine)
	masterPrivKeyScalar := new(big.Int).SetBytes(privateMasterKey.Scalar[:])
	common.ScalarMultG2(userPrivKey, &idH, masterPrivKeyScalar)
	return userPrivKey, nil
}
