package main

import (
	"opensm/src/sm4"
	"testing"
	"bytes"
)

func TestBlockSize(t *testing.T) {
	key := []uint8{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}
	plain := []uint8{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}

	expected1 := []uint8{0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E, 0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46}
	expected2 := []uint8{0x59, 0x52, 0x98, 0xC7, 0xC6, 0xFD, 0x27, 0x1F, 0x04, 0x02, 0xF8, 0x04, 0xC3, 0x3D, 0x3F, 0x66}

	cipher := make([]uint8, 16)
	plain2 := make([]uint8, 16)

	sm4, _ := sm4.NewCipher(key)

	block := sm4.BlockSize()
	t.Logf("block size : %d\n", block)

	sm4.Encrypt(cipher, plain)
	if bytes.Equal(cipher, expected1) {
		t.Logf("Encrypt test success!")
	} else {
		t.Errorf("Encrypt test failed!")
	}

	sm4.Decrypt(plain2, cipher)
	if bytes.Equal(plain, plain2) {
		t.Logf("Decrypt test success!")
	} else {
		t.Errorf("Decrypt test failed!")
	}

	p := plain
	round := 1000000
	for i := 0; i < round; i++ {
		sm4.Encrypt(cipher, p)
		p = cipher
	}

	if bytes.Equal(cipher, expected2) {
		t.Logf("Encrypt %d round success!", round)
	} else {
		t.Logf("Encrypt %d round failed!", round)
	}

	p = cipher
	for i := 0; i < round; i++ {
		sm4.Decrypt(plain2, p)
		p = plain2
	}
	if bytes.Equal(plain, plain2) {
		t.Logf("Encrypt %d round success!", round)
	} else {
		t.Logf("Decrypt %d round failed!", round)
	}
}