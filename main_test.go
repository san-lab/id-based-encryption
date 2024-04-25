package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/san-lab/id-based-encryption/client"
	"github.com/san-lab/id-based-encryption/common"
	"github.com/san-lab/id-based-encryption/tpkg"
)

/*

Setup

G1 x G2 -> G3

order(G1) = q1
P1 gen of G1
order(G2) = q2
P2 gen of G2

s in {0,1}^q1
sP1 in G1


Extraction

id in {0,1}^n
Q = H2(id) in G2
sQ in G2


Encryption

msg in {0,1}^n
id in {0,1}^n
Q = H2(id) in G2
r in {0,1}^q1

rP1 in G1
g = e(sP1, Q) in G3
V = m xor H3(g^r) in {0,1}^n
C = rP1, V


Decryption

C = (U, V)
e(sQ, U) in G3
V xor H3(e(sQ, U)) in {0,1}^n

*/

func TestFlow(t *testing.T) {
	tpkg.Initialize()

	ID := []byte("juan@gmail.com")
	juanPrivKey, err := tpkg.Extract(ID, nil)
	fmt.Println(err)

	MSG := []byte("happy birthday")
	ciphertext, err := client.Encrypt(ID, MSG)
	fmt.Println(err)

	plaintext, err := client.Decrypt(juanPrivKey, ciphertext)
	fmt.Println(err)
	fmt.Println(bytes.Equal(common.PAD(MSG, len(plaintext)), plaintext))
	fmt.Println(string(plaintext))
}

func TestFormats(t *testing.T) {
	tpkg.Initialize()

	ID := []byte("juan@gmail.com")
	juanPrivKey, err := tpkg.Extract(ID, nil)
	fmt.Println(err)
	fmt.Printf("Juan priv key: %v\n", juanPrivKey)

	juanPrivKeyMarshalled := juanPrivKey.Marshal()
	fmt.Printf("Juan priv key marshalled: %v\n", juanPrivKeyMarshalled)

	juanPrivKeyUnmarshalled := new(bls12381.G2Affine)
	juanPrivKeyUnmarshalled.Unmarshal(juanPrivKeyMarshalled)
	fmt.Printf("Juan priv key unmarshalled: %v\n", juanPrivKeyUnmarshalled)

	MSG := []byte("happy birthday")
	ciphertext, err := client.Encrypt(ID, MSG)
	fmt.Println(err)
	fmt.Printf("Ciphertext: %v\n", ciphertext)

	ciphertextMarshalled, err := json.Marshal(ciphertext)
	fmt.Println(err)
	fmt.Printf("Ciphertext marshalled: %v\n", ciphertextMarshalled)

	ciphertextUnmarshalled := new(client.BLSCiphertext)
	json.Unmarshal(ciphertextMarshalled, ciphertextUnmarshalled)
	fmt.Printf("Ciphertext unmarshalled: %v\n", ciphertextUnmarshalled)
	/*
	   req2 := client.DecryptRequest2{UserPrivKey: juanPrivKeyMarshalled, Ciphertext: ciphertextMarshalled}
	   json.Unmarshal()
	*/
}

func TestPubPrivMarshal(t *testing.T) {
	tpkg.Initialize()
	pub := tpkg.GetPublicMasterKey()
	fmt.Println(pub)

	pubM, err := pub.Marshal()
	fmt.Println(err, pubM)

	pubU := new(common.PublicKey)
	err = pubU.Unmarshal(pubM)
	fmt.Println(err, pubU)

	pubU2 := common.PublicKey{}
	err = pubU2.Unmarshal(pubM)
	fmt.Println(err, pubU2)
}
