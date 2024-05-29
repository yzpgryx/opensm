package sm2

import (
	"io"
	"fmt"
	"sync"
	"crypto/elliptic"
	"math/big"
	"crypto/rand"
)

var initonce sync.Once
var sm2p256 SM2P256Curve

type SM2P256Curve struct {
	A *big.Int
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
	elliptic.Curve
	*AffinePoint
}

type PrivateKey struct {
	*PublicKey
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

func initSM2P256() {
	sm2p256.params = &elliptic.CurveParams {
		Name: "SM2-P256",
		BitSize: 256,
		P: bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
		N: bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
		B: bigFromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
		Gx: bigFromHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
		Gy: bigFromHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
	}
	sm2p256.A = bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
}

func iAffine2Jacobian(point *AffinePoint) *JacobianPoint {
	return &JacobianPoint{
		X: new(big.Int).Set(point.X),
		Y: new(big.Int).Set(point.Y),
		Z: big.NewInt(1),
	}
}

func iJacobian2Affine(point *JacobianPoint, p *big.Int) *AffinePoint {
	zInv := new(big.Int).ModInverse(point.Z, p)
	zInv2 := new(big.Int).Mul(zInv, zInv)
	zInv3 := new(big.Int).Mul(zInv2, zInv)
	x := new(big.Int).Mod(new(big.Int).Mul(point.X, zInv2), p)
	y := new(big.Int).Mod(new(big.Int).Mul(point.Y, zInv3), p)
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
	if(curve.params != sm2p256.params) {
		return nil, nil
	}

	P := iAffine2Jacobian(&AffinePoint{X : x1, Y : y1})
	Q := iAffine2Jacobian(&AffinePoint{X : x2, Y : y2})

	if P.Z.Sign() == 0 {
		return x2, y2
	}
	if Q.Z.Sign() == 0 {
		return x1, y1
	}

	zz1 := ModMul(P.Z, P.Z, curve.params.P)
	zz2 := ModMul(Q.Z, Q.Z, curve.params.P)
	zzz2 := ModMul(zz2, Q.Z, curve.params.P)
	zzz1 := ModMul(zz1, P.Z, curve.params.P)

	u1 := ModMul(P.X, zz2, curve.params.P)
	u2 := ModMul(Q.X, zz1, curve.params.P)
	s1 := ModMul(P.Y, zzz2, curve.params.P)
	s2 := ModMul(Q.Y, zzz1, curve.params.P)
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

	z3 := ModMul(P.Z, Q.Z, curve.params.P)
	z3 = ModMul(z3, h, curve.params.P)

	R := iJacobian2Affine(&JacobianPoint{
		X: x3,
		Y: y3,
		Z: z3,
	}, curve.params.P)

	return R.X, R.Y
}

func (curve SM2P256Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	p := iAffine2Jacobian(&AffinePoint{
		X: x1,
		Y: y1,
	})

	if p.Z.Sign() == 0 {
		return x1, y1
	}

	xx := ModMul(p.X, p.X, curve.params.P)
	xxxx := ModMul(xx, xx, curve.params.P)
	yy := ModMul(p.Y, p.Y, curve.params.P)
	yyyy := ModMul(yy, yy, curve.params.P)
	xyy := ModMul(p.X, yy, curve.params.P)

	x3 := ModMul(big.NewInt(9), xxxx, curve.params.P)
	t := ModMul(big.NewInt(8), xyy, curve.params.P)
	x3 = ModSub(x3 ,t, curve.params.P)

	y3 := ModMul(big.NewInt(3), xx, curve.params.P)
	t = ModMul(big.NewInt(4), xyy, curve.params.P)
	t = ModSub(t, x3, curve.params.P)
	y3 = ModMul(y3, t, curve.params.P)
	t = ModMul(big.NewInt(8), yyyy, curve.params.P)
	y3 = ModSub(y3, t, curve.params.P)

	z3 := ModMul(big.NewInt(2), p.Y, curve.params.P)
	z3 = ModMul(z3, p.Z, curve.params.P)

	r := iJacobian2Affine(&JacobianPoint{
		X: x3,
		Y: y3,
		Z: z3,
	}, curve.params.P)

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
	r0X, r0Y := big.NewInt(0), big.NewInt(0)
	r1X, r1Y := x1, y1

	K := new(big.Int).SetBytes(k)

	for i := K.BitLen() - 1; i >= 0; i-- {
		if K.Bit(i) == 0 {
			r1X, r1Y = curve.Add(r0X, r0Y, r1X, r1Y)
			r0X, r0Y = curve.Double(r0X, r0Y)
		} else {
			r0X, r0Y = curve.Add(r0X, r0Y, r1X, r1Y)
			r1X, r1Y = curve.Double(r1X, r1Y)
		}
	}

	r0X.Mod(r0X, curve.params.P)
	r0Y.Mod(r0Y, curve.params.P)

	return r0X, r0Y
	// R0 := Point{0, 0} // Point at infinity
    // R1 := P
    // for i := k.BitLen() - 1; i >= 0; i-- {
    //     if k.Bit(i) == 0 {
    //         R1 = R0.Add(R1)
    //         R0 = R0.Double()
    //     } else {
    //         R0 = R0.Add(R1)
    //         R1 = R1.Double()
    //     }
    // }
    // return R0
}

func SM2P256() elliptic.Curve {
	initonce.Do(initAll)
	return sm2p256;
}

func GenerateKeySM2P256(random io.Reader) *PrivateKey {
	if random == nil {
		random = rand.Reader
	}

	// d := bigFromHex("8F09E6F801D47FF182C70A8904F63576135FDD09BD7DC8574C5D4D24F4F236F2")
	x := bigFromHex("C08C3983284907D86B4A5E8E8718D6FC16DDA37C3D03A92FA423325908EBF998")
	y := bigFromHex("D0A878C58949FDEB906EE4FDDD32A2D38F42AE56A71A811D30E9EBA0BFE7642C")

	curve := SM2P256()
	// nMinusTwo := new(big.Int).Sub(curve.Params().P, big.NewInt(2))
	// d, _ := rand.Int(random, nMinusTwo)
	// d.Add(d, big.NewInt(1))

	// fmt.Printf("private key : %x\n", d.Bytes())

	// x, y := curve.ScalarBaseMult(d.Bytes())
	// fmt.Printf("publickey key :\n%x\n%x\n", x.Bytes(), y.Bytes())

	if curve.IsOnCurve(x, y) {
		fmt.Printf("publickey is on curve!\n")
	} else {
		fmt.Printf("publickey is not on curve!\n")
	}

	return nil
}