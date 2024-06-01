package main

import (
	"opensm/src/sm2"
	"testing"
	"crypto/rand"
)

func TestGenerateKeySM2P256(t *testing.T) {
	pkey, _ := sm2.GenerateKeySM2P256(nil)
	if pkey != nil {
		t.Logf("generete sm2 keypair success!")
	} else {
		t.Errorf("generete sm2 keypair failed!")
	}
}

func TestSign(t *testing.T) {
	msg := make([]byte, 32)
	_, err := rand.Read(msg)
	if err != nil {
		t.Errorf("generate rand message failed")
	}

	pkey, _ := sm2.GenerateKeySM2P256(nil)
	if pkey != nil {
		t.Logf("generete sm2 keypair success!")
	} else {
		t.Errorf("generete sm2 keypair failed!")
	}

	r, s, err := sm2.Sign(nil, pkey, msg)
	if err != nil {
		t.Errorf("sign failed : %s", err)
	}

	t.Logf("r : %x\ns : %x\n", r, s)
}