package sm3

import (
	"encoding/binary"
	"hash"
	"opensm/src/util"
)

const BlockSize = 64
const Size = 32

type SM3 struct {
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

func xorShiftP0(x uint32) uint32 {
	return x ^ util.RotateLeft(x, 9) ^ util.RotateLeft(x, 17)
}

func xorShiftP1(x uint32) uint32 {
	return x ^ util.RotateLeft(x, 15) ^ util.RotateLeft(x, 23)
}

func Expand(b []uint32) []uint32 {
	w := make([]uint32, 132)
	copy(w, b)

	for j := 16; j <= 67; j++ {
		w[j] = xorShiftP1(w[j-16]^w[j-9]^(util.RotateLeft(w[j-3], 15))) ^ util.RotateLeft(w[j-13], 7) ^ w[j-6]
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
		SS1 = util.RotateLeft((util.RotateLeft(A, 12) + E + util.RotateLeft(T(j), j)), 7)
		SS2 = SS1 ^ (util.RotateLeft(A, 12))
		TT1 = FF(A, B, C, j) + D + SS2 + W[68+j]
		TT2 = GG(E, F, G, j) + H + SS1 + W[j]
		D = C
		C = util.RotateLeft(B, 9)
		B = A
		A = TT1
		H = G
		G = util.RotateLeft(F, 19)
		F = E
		E = xorShiftP0(TT2)
	}

	return []uint32{A, B, C, D, E, F, G, H}
}

func (sm3 *SM3) BlockSize() int {
	return BlockSize
}

func (sm3 *SM3) Reset() {
	sm3.length = 0
	sm3.x = sm3.x[:0]
	sm3.A = 0x7380166f
	sm3.B = 0x4914b2b9
	sm3.C = 0x172442d7
	sm3.D = 0xda8a0600
	sm3.E = 0xa96f30bc
	sm3.F = 0x163138aa
	sm3.G = 0xe38dee4d
	sm3.H = 0xb0fb0e4e
}

func (sm3 *SM3) Size() int {
	return Size
}

func update(sm3 *SM3, p []byte, update bool) (int, []uint32) {
	var b [BlockSize / 4]uint32
	var W []uint32
	var i int

	A, B, C, D, E, F, G, H := sm3.A, sm3.B, sm3.C, sm3.D, sm3.E, sm3.F, sm3.G, sm3.H
	for i = 0; i < len(p)/BlockSize; i++ {
		for j := 0; j < BlockSize/4; j++ {
			b[j] = binary.BigEndian.Uint32(p[i*BlockSize+j*4 : i*BlockSize+(j+1)*4])
		}

		W = Expand(b[:])
		dgst := CF(A, B, C, D, E, F, G, H, W)
		A = A ^ dgst[0]
		B = B ^ dgst[1]
		C = C ^ dgst[2]
		D = D ^ dgst[3]
		E = E ^ dgst[4]
		F = F ^ dgst[5]
		G = G ^ dgst[6]
		H = H ^ dgst[7]
	}

	if update {
		sm3.A, sm3.B, sm3.C, sm3.D, sm3.E, sm3.F, sm3.G, sm3.H = A, B, C, D, E, F, G, H
	}

	return i, []uint32{A, B, C, D, E, F, G, H}
}

func (sm3 *SM3) Sum(b []byte) []byte {
	data := padding(sm3, sm3.x)

	nblocks, sum := update(sm3, data, false)
	sm3.x = sm3.x[(nblocks-1)*BlockSize:]
	dgst := make([]byte, 32)

	for i := 0; i < len(sum); i++ {
		binary.BigEndian.PutUint32(dgst[i*4:], sum[i])
	}

	b = append(b, dgst...)
	return b
}

func (sm3 *SM3) Write(p []byte) (n int, err error) {
	sm3.x = append(sm3.x, p...)
	sm3.length += len(p)
	nblocks, _ := update(sm3, p, true)
	sm3.x = sm3.x[nblocks*BlockSize:]
	return len(p), nil
}

func New() hash.Hash {
	sm3 := new(SM3)

	sm3.Reset()
	return sm3
}
