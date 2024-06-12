package sm3

import (
	"encoding/binary"
	"hash"
	"strconv"
)

const BlockSize = 64
const Size = 32

type SM3 struct {
	dgst   []byte
	length int
	x      []byte
	A      uint32
	B      uint32
	C      uint32
	D      uint32
	E      uint32
	F      uint32
	G      uint32
	H      uint32
}

func T(j uint) uint32 {
	if j <= 15 {
		return 0x79cc4519
	} else if j <= 63 {
		return 0x7a879d8a
	}

	// should never happen
	return 0
}

func padding(sm3 *SM3, p []byte) []byte {
	block := (len(p) + 9) / BlockSize
	if (len(p)+9)%BlockSize != 0 {
		block++
	}

	padlen := uint64(block*BlockSize - len(p))

	data := make([]byte, uint64(len(p))+padlen)
	copy(data, p)
	data[len(p)] = 0x80
	binary.BigEndian.PutUint64(data[len(data)-8:], uint64(sm3.length*8))

	return data
}

func FF(x, y, z uint32, j uint) uint32 {
	if j <= 15 {
		return x ^ y ^ z
	} else if j <= 63 {
		return (x & y) | (x & z) | (y & z)
	}

	// should never happen
	return 0
}

func GG(x, y, z uint32, j uint) uint32 {
	if j <= 15 {
		return x ^ y ^ z
	} else if j <= 63 {
		return (x & y) | (^x & z)
	}

	// should never happen
	return 0
}

func rotateLeft(x uint32, k uint) uint32 {
	k %= 32
	return (x << k) | (x >> (32 - k))
}

func xorShiftP0(x uint32) uint32 {
	return x ^ rotateLeft(x, 9) ^ rotateLeft(x, 17)
}

func xorShiftP1(x uint32) uint32 {
	return x ^ rotateLeft(x, 15) ^ rotateLeft(x, 23)
}

func Expand(b []uint32) []uint32 {
	w := make([]uint32, 132)
	copy(w, b)

	for j := 16; j <= 67; j++ {
		w[j] = xorShiftP1(w[j-16]^w[j-9]^(rotateLeft(w[j-3], 15))) ^ rotateLeft(w[j-13], 7) ^ w[j-6]
	}

	for j := 0; j <= 63; j++ {
		w[j+68] = w[j] ^ w[j+4]
	}

	return w
}

func CF(A, B, C, D, E, F, G, H uint32, W []uint32) []uint32 {
	var SS1, SS2, TT1, TT2 uint32
	var j uint

	for j = 0; j < BlockSize; j++ {
		SS1 = rotateLeft((rotateLeft(A, 12) + E + rotateLeft(T(j), j)), 7)
		SS2 = SS1 ^ (rotateLeft(A, 12))
		TT1 = FF(A, B, C, j) + D + SS2 + W[68+j]
		TT2 = GG(E, F, G, j) + H + SS1 + W[j]
		D = C
		C = rotateLeft(B, 9)
		B = A
		A = TT1
		H = G
		G = rotateLeft(F, 19)
		F = E
		E = xorShiftP0(TT2)
	}

	return []uint32{A, B, C, D, E, F, G, H}
}

func (sm3 *SM3) BlockSize() int {
	return BlockSize
}

func hexstr2uint32(str string) uint32 {
	value, _ := strconv.ParseUint(str, 16, 32)
	return uint32(value)
}

func (sm3 *SM3) Reset() {
	sm3.dgst = make([]byte, 32)
	sm3.length = 0
	sm3.x = sm3.x[:0]
	sm3.A = hexstr2uint32("7380166f")
	sm3.B = hexstr2uint32("4914b2b9")
	sm3.C = hexstr2uint32("172442d7")
	sm3.D = hexstr2uint32("da8a0600")
	sm3.E = hexstr2uint32("a96f30bc")
	sm3.F = hexstr2uint32("163138aa")
	sm3.G = hexstr2uint32("e38dee4d")
	sm3.H = hexstr2uint32("b0fb0e4e")
}

func (sm3 *SM3) Size() int {
	return Size
}

func update(sm3 *SM3, p []byte) int {
	var B [BlockSize / 4]uint32
	var W []uint32
	var i int

	for i = 0; i < len(p)/BlockSize; i++ {
		for j := 0; j < BlockSize/4; j++ {
			B[j] = binary.BigEndian.Uint32(p[i*BlockSize+j*4 : i*BlockSize+(j+1)*4])
		}

		W = Expand(B[:])
		dgst := CF(sm3.A, sm3.B, sm3.C, sm3.D, sm3.E, sm3.F, sm3.G, sm3.H, W)
		sm3.A = sm3.A ^ dgst[0]
		sm3.B = sm3.B ^ dgst[1]
		sm3.C = sm3.C ^ dgst[2]
		sm3.D = sm3.D ^ dgst[3]
		sm3.E = sm3.E ^ dgst[4]
		sm3.F = sm3.F ^ dgst[5]
		sm3.G = sm3.G ^ dgst[6]
		sm3.H = sm3.H ^ dgst[7]
	}

	return i
}

func (sm3 *SM3) Sum(b []byte) []byte {
	sm3.x = append(sm3.x, b...)
	sm3.length += len(b)
	data := padding(sm3, sm3.x)

	nblocks := update(sm3, data)
	sm3.x = sm3.x[(nblocks-1)*BlockSize:]
	binary.BigEndian.PutUint32(sm3.dgst[0:], sm3.A)
	binary.BigEndian.PutUint32(sm3.dgst[4:], sm3.B)
	binary.BigEndian.PutUint32(sm3.dgst[8:], sm3.C)
	binary.BigEndian.PutUint32(sm3.dgst[12:], sm3.D)
	binary.BigEndian.PutUint32(sm3.dgst[16:], sm3.E)
	binary.BigEndian.PutUint32(sm3.dgst[20:], sm3.F)
	binary.BigEndian.PutUint32(sm3.dgst[24:], sm3.G)
	binary.BigEndian.PutUint32(sm3.dgst[28:], sm3.H)
	return sm3.dgst
}

func (sm3 *SM3) Write(p []byte) (n int, err error) {
	sm3.x = append(sm3.x, p...)
	sm3.length += len(p)
	nblocks := update(sm3, p)
	sm3.x = sm3.x[nblocks*BlockSize:]
	return len(p), nil
}

func New() hash.Hash {
	sm3 := new(SM3)

	sm3.Reset()
	return sm3
}
