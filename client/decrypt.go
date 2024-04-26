package client

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/san-lab/id-based-encryption/common"
)

func Decrypt(userPrivKey *bls12381.G2Affine, ciphertext BLSCiphertext) ([]byte, error) {
	//fmt.Printf("Decrypt %v, %v", userPrivKey, ciphertext)
	// Calculate m = V xor H3(e(rP, sidH))
	pair, err := common.PairG1G2(*ciphertext.U, *userPrivKey)
	if err != nil {
		return nil, err
	}
	pair_H := common.H3(pair)
	plaintext, err := common.XOR(ciphertext.V, pair_H)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
