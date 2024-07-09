package util

func RotateLeft(x uint32, k uint) uint32 {
	k %= 32
	return (x << k) | (x >> (32 - k))
}
