package main

import (
	"testing"
	"opensm/src/sm2"
)

func TestGenerateKeySM2P256(t *testing.T) {
	pkey := sm2.GenerateKeySM2P256(nil)
	if pkey != nil {
		t.Logf("generete sm2 keypair success!")
	} else {
		t.Errorf("generete sm2 keypair failed!")
	}
}

