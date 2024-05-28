package main

import (
	"testing"
	"opensm/src/sm2"
)

func TestSM2P256(t *testing.T) {
	sm2p256 := sm2.SM2P256()
	sm2p256.Params()

	t.Logf("hehe")
}