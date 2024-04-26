package common

import (
	"fmt"
	"testing"
)

func TestXor(t *testing.T) {
	a := []byte{0, 1}
	b := []byte{0, 1}
	c := []byte{1, 3}
	fmt.Println(XOR(a, b))
	fmt.Println(XOR(b, c))
}

func TestPad(t *testing.T) {
	a := []byte{0, 1}
	fmt.Println(PAD(a, 10))
	fmt.Println(PAD(a, 20))
	fmt.Println(PAD(a, 1))
	fmt.Println(PAD(a, -1))
}

func TestUnpad(t *testing.T) {
	a := []byte{0, 0, 3, 4}
	b := []byte{3, 4}
	fmt.Println(a, b)
	fmt.Println(UNPAD(a), UNPAD(b))
}
