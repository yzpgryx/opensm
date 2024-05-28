package sm2

import (
	"io"
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

type Point struct {
	X *big.Int
	Y *big.Int
}

type PublicKey struct {
	elliptic.Curve
	*Point
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

func initAll() {
	initSM2P256()
}

func (curve SM2P256Curve) Params() *elliptic.CurveParams {
	return curve.params
}

func (curve SM2P256Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	if(curve.params != sm2p256.params) {
		return nil, nil
	}

	// 1. 如果任意一点为无穷远点，则返回另一点
	if x1 == nil || y1 == nil {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}

    if x2 == nil || y2 == nil {
        return new(big.Int).Set(x1), new(big.Int).Set(y1)
    }

    // 2. 斜率λ=(y2 - y1) / (x2 - x1)
    lambda := new(big.Int).Sub(y2, y1)
    denom := new(big.Int).Sub(x2, x1)
    denom.ModInverse(lambda, curve.params.P)
    lambda.Mul(lambda, denom)
    lambda.Mod(lambda, curve.params.P)

    // 3. x = λ^2 - x1 - x2, y = λ(x1 - x3) - y1
    x = new(big.Int).Mul(lambda, lambda)
    x.Sub(x, x1)
    x.Sub(x, x2)
    x.Mod(x, curve.params.P)

    y = new(big.Int).Sub(x1, x)
    y.Mul(y, lambda)
    y.Sub(y, y1)
    y.Mod(y, curve.params.P)

    return x, y
}

func (curve SM2P256Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return nil, nil
}

func (curve SM2P256Curve) IsOnCurve(x, y *big.Int) bool {
	return true
}

func (curve SM2P256Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return nil, nil
}

func (curve SM2P256Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	return nil, nil
}

func SM2P256() elliptic.Curve {
	initonce.Do(initAll)
	return sm2p256;
}

func GenerateKeySM2P256(random io.Reader) {
	curve := SM2P256()

	if random == nil {
		random = rand.Reader
	}

	d, _ := rand.Int(random, curve.Params().P)
	
}