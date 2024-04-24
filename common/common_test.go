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
