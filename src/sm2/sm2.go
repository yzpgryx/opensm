package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"sync"
)

var initonce sync.Once
var sm2p256 SM2P256Curve

type SM2P256Curve struct {
	A      *big.Int
	params *elliptic.CurveParams
}

type JacobianPoint struct {
	X *big.Int
	Y *big.Int
	Z *big.Int
}

type AffinePoint struct {
	X *big.Int
	Y *big.Int
}

type PublicKey struct {
	curve *elliptic.Curve
	*AffinePoint
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

type Signature struct {
	R *big.Int
	S *big.Int
}

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("opensm/sm2: internal error: invalid encoding")
	}
	return b
}

func bigFromDec(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("opensm/sm2: internal error: invalid encoding")
	}
	return b
}

func initSM2P256() {
	sm2p256.params = &elliptic.CurveParams{
		Name:    "SM2-P256",
		BitSize: 256,
		P:       bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
		N:       bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
		B:       bigFromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
		Gx:      bigFromHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
		Gy:      bigFromHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
	}
	sm2p256.A = bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
}

func iAffine2Jacobian(point *AffinePoint) *JacobianPoint {
	Z := 1

	if point.X.Sign() == 0 && point.Y.Sign() == 0 {
		Z = 0
	}

	return &JacobianPoint{
		X: new(big.Int).Set(point.X),
		Y: new(big.Int).Set(point.Y),
		Z: big.NewInt(int64(Z)),
	}
}

func iJacobian2Affine(point *JacobianPoint, prime *big.Int) *AffinePoint {
	zInv := new(big.Int).ModInverse(point.Z, prime)
	zInv2 := new(big.Int).Mul(zInv, zInv)
	zInv3 := new(big.Int).Mul(zInv2, zInv)
	x := new(big.Int).Mod(new(big.Int).Mul(point.X, zInv2), prime)
	y := new(big.Int).Mod(new(big.Int).Mul(point.Y, zInv3), prime)
	return &AffinePoint{
		X: x,
		Y: y,
	}
}

func initAll() {
	initSM2P256()
}

func (curve SM2P256Curve) Params() *elliptic.CurveParams {
	return curve.params
}

// r = x + y mod n
func ModAdd(x, y, n *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(x, y), n)
}

// r = x - y mod n
func ModSub(x, y, n *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Sub(x, y), n)
}

// r = x * y mod n
func ModMul(x, y, n *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(x, y), n)
}

func (curve SM2P256Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	if curve.params != sm2p256.params {
		return nil, nil
	}

	p := iAffine2Jacobian(&AffinePoint{X: x1, Y: y1})
	q := iAffine2Jacobian(&AffinePoint{X: x2, Y: y2})

	r := iJacobian2Affine(JacoianPointAdd(curve, p, q), curve.params.P)

	return r.X, r.Y
}

func (curve SM2P256Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	p := iAffine2Jacobian(&AffinePoint{
		X: x1,
		Y: y1,
	})

	r := iJacobian2Affine(JacoianPointDouble(curve, p), curve.params.P)

	return r.X, r.Y
}

func (curve SM2P256Curve) IsOnCurve(x, y *big.Int) bool {
	yy := ModMul(y, y, curve.params.P)

	xx := ModMul(x, x, curve.params.P)
	xxx := ModMul(xx, x, curve.params.P)

	ax := ModMul(curve.A, x, curve.params.P)

	right := ModAdd(xxx, ax, curve.params.P)
	right = ModAdd(right, curve.params.B, curve.params.P)

	return right.Cmp(yy) == 0
}

func (curve SM2P256Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return curve.ScalarMult(curve.params.Gx, curve.params.Gy, k)
}

func (curve SM2P256Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	r0 := iAffine2Jacobian(&AffinePoint{X: big.NewInt(0), Y: big.NewInt(0)})
	r1 := iAffine2Jacobian(&AffinePoint{X: x1, Y: y1})

	K := new(big.Int).SetBytes(k)

	for i := K.BitLen() - 1; i >= 0; i-- {
		if K.Bit(i) == 0 {
			r1 = JacoianPointAdd(curve, r0, r1)
			r0 = JacoianPointDouble(curve, r0)
		} else {
			r0 = JacoianPointAdd(curve, r0, r1)
			r1 = JacoianPointDouble(curve, r1)
		}
	}

	r := iJacobian2Affine(r0, curve.params.P)

	return r.X, r.Y
}

func JacoianPointAdd(curve SM2P256Curve, p *JacobianPoint, q *JacobianPoint) *JacobianPoint {
	if p.Z.Sign() == 0 {
		return q
	}
	if q.Z.Sign() == 0 {
		return p
	}

	zz1 := ModMul(p.Z, p.Z, curve.params.P)
	zz2 := ModMul(q.Z, q.Z, curve.params.P)
	zzz2 := ModMul(zz2, q.Z, curve.params.P)
	zzz1 := ModMul(zz1, p.Z, curve.params.P)

	u1 := ModMul(p.X, zz2, curve.params.P)
	u2 := ModMul(q.X, zz1, curve.params.P)
	s1 := ModMul(p.Y, zzz2, curve.params.P)
	s2 := ModMul(q.Y, zzz1, curve.params.P)
	h := ModSub(u2, u1, curve.params.P)
	r := ModSub(s2, s1, curve.params.P)
	rr := ModMul(r, r, curve.params.P)
	hh := ModMul(h, h, curve.params.P)
	hhh := ModMul(hh, h, curve.params.P)

	x3 := ModSub(rr, hhh, curve.params.P)
	u1hh := ModMul(u1, hh, curve.params.P)
	x3 = ModSub(x3, ModMul(big.NewInt(2), u1hh, curve.params.P), curve.params.P)

	y3 := ModSub(u1hh, x3, curve.params.P)
	y3 = ModMul(y3, r, curve.params.P)
	y3 = ModSub(y3, ModMul(s1, hhh, curve.params.P), curve.params.P)

	z3 := ModMul(p.Z, q.Z, curve.params.P)
	z3 = ModMul(z3, h, curve.params.P)

	return &JacobianPoint{
		X: x3,
		Y: y3,
		Z: z3,
	}
}

func JacoianPointDouble(curve SM2P256Curve, p *JacobianPoint) *JacobianPoint {
	if p.Z.Sign() == 0 {
		return p
	}

	xx := ModMul(p.X, p.X, curve.params.P)
	yy := ModMul(p.Y, p.Y, curve.params.P)
	yyyy := ModMul(yy, yy, curve.params.P)
	zz := ModMul(p.Z, p.Z, curve.params.P)
	zzzz := ModMul(zz, zz, curve.params.P)

	s := ModMul(big.NewInt(4), p.X, curve.params.P)
	s = ModMul(s, yy, curve.params.P)

	m := ModMul(big.NewInt(3), xx, curve.params.P)
	t := ModMul(curve.A, zzzz, curve.params.P)
	m = ModAdd(m, t, curve.params.P)

	x3 := ModMul(m, m, curve.params.P)
	t = ModMul(big.NewInt(2), s, curve.params.P)
	x3 = ModSub(x3, t, curve.params.P)

	y3 := ModSub(s, x3, curve.params.P)
	y3 = ModMul(m, y3, curve.params.P)
	t = ModMul(big.NewInt(8), yyyy, curve.params.P)
	y3 = ModSub(y3, t, curve.params.P)

	z3 := ModMul(big.NewInt(2), p.Y, curve.params.P)
	z3 = ModMul(z3, p.Z, curve.params.P)

	return &JacobianPoint{
		X: x3,
		Y: y3,
		Z: z3,
	}
}

func SM2P256() elliptic.Curve {
	initonce.Do(initAll)
	return sm2p256
}

func GenerateKeySM2P256(random io.Reader) (*PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}

	// d := bigFromHex("8F09E6F801D47FF182C70A8904F63576135FDD09BD7DC8574C5D4D24F4F236F2")
	// x := bigFromHex("C08C3983284907D86B4A5E8E8718D6FC16DDA37C3D03A92FA423325908EBF998")
	// y := bigFromHex("D0A878C58949FDEB906EE4FDDD32A2D38F42AE56A71A811D30E9EBA0BFE7642C")

	curve := SM2P256()
	nMinusTwo := new(big.Int).Sub(curve.Params().P, big.NewInt(2))
	d, _ := rand.Int(random, nMinusTwo)
	d.Add(d, big.NewInt(1))

	fmt.Printf("private key : %x\n", d.Bytes())

	x, y := curve.ScalarBaseMult(d.Bytes())
	fmt.Printf("publickey key :\n%x\n%x\n", x.Bytes(), y.Bytes())

	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("publickey is not on curve\n")
	}

	return &PrivateKey{
		PublicKey: PublicKey{
			curve: &curve,
			AffinePoint: &AffinePoint{
				X: x,
				Y: y,
			},
		},
		D: d,
	}, nil
}

func Sign(random io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	if random == nil {
		random = rand.Reader
	}

	if priv == nil || hash == nil {
		return nil, nil, fmt.Errorf("invalid args\n")
	}

	curve := SM2P256()
	nMinusOne := new(big.Int).Sub(curve.Params().P, big.NewInt(1))

randk:
	k, _ := rand.Int(random, nMinusOne)
	k.Add(k, big.NewInt(1))

	m := new(big.Int).SetBytes(hash)
	x, _ := curve.ScalarBaseMult(k.Bytes())
	r = ModAdd(m, x, curve.Params().N)

	t := ModAdd(r, k, curve.Params().N)
	if r.Sign() == 0 || t.Sign() == 0 {
		goto randk
	}

	s = ModAdd(big.NewInt(1), priv.D, curve.Params().N)
	s.ModInverse(s, curve.Params().N)
	t = ModMul(r, priv.D, curve.Params().N)
	t = ModSub(k, t, curve.Params().N)
	s = ModMul(s, t, curve.Params().N)
	if s.Sign() == 0 {
		goto randk
	}

	return r, s, nil
}

func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	if pub == nil || hash == nil || r == nil || s == nil {
		return false
	}

	curve := SM2P256()

	if r.Sign() != 1 || r.Cmp(curve.Params().N) != -1 || s.Sign() != 1 || s.Cmp(curve.Params().N) != -1 {
		return false
	}

	t := ModAdd(r, s, curve.Params().N)
	if t.Sign() == 0 {
		return false
	}

	x2, y2 := curve.ScalarBaseMult(s.Bytes())
	x3, y3 := curve.ScalarMult(pub.X, pub.Y, t.Bytes())

	x1, _ := curve.Add(x2, y2, x3, y3)

	e := new(big.Int).SetBytes(hash)
	R := ModAdd(e, x1, curve.Params().N)

	if r.Cmp(R) == 0 {
		return true
	} else {
		return false
	}
}
