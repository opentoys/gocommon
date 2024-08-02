package gmsm

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
	"sync"
)

// P256OrdInverse, sets out to in⁻¹ mod org(G). If in is zero, out will be zero.
// n-2 =
// 1111111111111111111111111111111011111111111111111111111111111111
// 1111111111111111111111111111111111111111111111111111111111111111
// 0111001000000011110111110110101100100001110001100000010100101011
// 0101001110111011111101000000100100111001110101010100000100100001
func P256OrdInverse(k []byte) ([]byte, error) {
	if len(k) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	x := new(SM2P256OrderElement)
	_1 := new(SM2P256OrderElement)
	_, err := _1.SetBytes(k)
	if err != nil {
		return nil, err
	}

	_11 := new(SM2P256OrderElement)
	_101 := new(SM2P256OrderElement)
	_111 := new(SM2P256OrderElement)
	_1111 := new(SM2P256OrderElement)
	_10101 := new(SM2P256OrderElement)
	_101111 := new(SM2P256OrderElement)
	t := new(SM2P256OrderElement)
	m := new(SM2P256OrderElement)

	m.Square(_1)
	_11.Mul(m, _1)
	_101.Mul(m, _11)
	_111.Mul(m, _101)
	x.Square(_101)
	_1111.Mul(_101, x)

	t.Square(x)
	_10101.Mul(t, _1)
	x.Square(_10101)
	_101111.Mul(x, _101)
	x.Mul(_10101, x)
	t.Square(x)
	t.Square(t)

	m.Mul(t, m)
	t.Mul(t, _11)
	x.Square(t)
	for i := 1; i < 8; i++ {
		x.Square(x)
	}
	m.Mul(x, m)
	x.Mul(x, t)

	t.Square(x)
	for i := 1; i < 16; i++ {
		t.Square(t)
	}
	m.Mul(t, m)
	t.Mul(t, x)

	x.Square(m)
	for i := 1; i < 32; i++ {
		x.Square(x)
	}
	x.Mul(x, t)
	for i := 0; i < 32; i++ {
		x.Square(x)
	}
	x.Mul(x, t)
	for i := 0; i < 32; i++ {
		x.Square(x)
	}
	x.Mul(x, t)

	sqrs := []uint8{
		4, 3, 11, 5, 3, 5, 1,
		3, 7, 5, 9, 7, 5, 5,
		4, 5, 2, 2, 7, 3, 5,
		5, 6, 2, 6, 3, 5,
	}
	muls := []*SM2P256OrderElement{
		_111, _1, _1111, _1111, _101, _10101, _1,
		_1, _111, _11, _101, _10101, _10101, _111,
		_111, _1111, _11, _1, _1, _1, _111,
		_111, _10101, _1, _1, _1, _1}

	for i, s := range sqrs {
		for j := 0; j < int(s); j++ {
			x.Square(x)
		}
		x.Mul(x, muls[i])
	}

	return x.Bytes(), nil

}

// P256OrdMul multiplication modulo org(G).
func P256OrdMul(in1, in2 []byte) ([]byte, error) {
	if len(in1) != 32 || len(in2) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	ax := new(SM2P256OrderElement)
	ay := new(SM2P256OrderElement)
	res := new(SM2P256OrderElement)

	_, err := ax.SetBytes(in1)
	if err != nil {
		return nil, err
	}

	_, err = ay.SetBytes(in2)
	if err != nil {
		return nil, err
	}

	res = res.Mul(ax, ay)
	return res.Bytes(), nil
}

var p256Order = [4]uint64{0x53bbf40939d54123, 0x7203df6b21c6052b,
	0xffffffffffffffff, 0xfffffffeffffffff}

func fromBytes(bytes []byte) (*[4]uint64, error) {
	if len(bytes) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	var t [4]uint64
	t[0] = binary.BigEndian.Uint64(bytes[24:])
	t[1] = binary.BigEndian.Uint64(bytes[16:])
	t[2] = binary.BigEndian.Uint64(bytes[8:])
	t[3] = binary.BigEndian.Uint64(bytes)
	return &t, nil
}

func sm2ec_toBytes(t *[4]uint64) []byte {
	var bytes [32]byte

	binary.BigEndian.PutUint64(bytes[:], t[3])
	binary.BigEndian.PutUint64(bytes[8:], t[2])
	binary.BigEndian.PutUint64(bytes[16:], t[1])
	binary.BigEndian.PutUint64(bytes[24:], t[0])

	return bytes[:]
}

// p256OrdAdd sets res = x + y.
func p256OrdAdd(res, x, y *[4]uint64) {
	var c, b uint64
	t1 := make([]uint64, 4)
	t1[0], c = bits.Add64(x[0], y[0], 0)
	t1[1], c = bits.Add64(x[1], y[1], c)
	t1[2], c = bits.Add64(x[2], y[2], c)
	t1[3], c = bits.Add64(x[3], y[3], c)
	t2 := make([]uint64, 4)
	t2[0], b = bits.Sub64(t1[0], p256Order[0], 0)
	t2[1], b = bits.Sub64(t1[1], p256Order[1], b)
	t2[2], b = bits.Sub64(t1[2], p256Order[2], b)
	t2[3], b = bits.Sub64(t1[3], p256Order[3], b)
	// Three options:
	//   - a+b < p
	//     then c is 0, b is 1, and t1 is correct
	//   - p <= a+b < 2^256
	//     then c is 0, b is 0, and t2 is correct
	//   - 2^256 <= a+b
	//     then c is 1, b is 1, and t2 is correct
	t2Mask := (c ^ b) - 1
	res[0] = (t1[0] & ^t2Mask) | (t2[0] & t2Mask)
	res[1] = (t1[1] & ^t2Mask) | (t2[1] & t2Mask)
	res[2] = (t1[2] & ^t2Mask) | (t2[2] & t2Mask)
	res[3] = (t1[3] & ^t2Mask) | (t2[3] & t2Mask)
}

func ImplicitSig(sPriv, ePriv, t []byte) ([]byte, error) {
	mulRes, err := P256OrdMul(ePriv, t)
	if err != nil {
		return nil, err
	}
	t1, err := fromBytes(mulRes)
	if err != nil {
		return nil, err
	}
	t2, err := fromBytes(sPriv)
	if err != nil {
		return nil, err
	}
	var t3 [4]uint64
	p256OrdAdd(&t3, t1, t2)
	return sm2ec_toBytes(&t3), nil
}

// sm2p256ElementLength is the length of an element of the base or scalar field,
// which have the same bytes length for all NIST P curves.
const sm2p256ElementLength = 32

// SM2P256Point is a SM2P256 point. The zero value is NOT valid.
type SM2P256Point struct {
	// The point is represented in projective coordinates (X:Y:Z),
	// where x = X/Z and y = Y/Z.
	x, y, z *SM2P256Element
}

// NewSM2P256Point returns a new SM2P256Point representing the point at infinity point.
func NewSM2P256Point() *SM2P256Point {
	return &SM2P256Point{
		x: new(SM2P256Element),
		y: new(SM2P256Element).One(),
		z: new(SM2P256Element),
	}
}

// SetGenerator sets p to the canonical generator and returns p.
func (p *SM2P256Point) SetGenerator() *SM2P256Point {
	p.x.SetBytes([]byte{0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x4, 0x46, 0x6a, 0x39, 0xc9, 0x94, 0x8f, 0xe3, 0xb, 0xbf, 0xf2, 0x66, 0xb, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7})
	p.y.SetBytes([]byte{0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53, 0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40, 0x2, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0})
	p.z.One()
	return p
}

// Set sets p = q and returns p.
func (p *SM2P256Point) Set(q *SM2P256Point) *SM2P256Point {
	p.x.Set(q.x)
	p.y.Set(q.y)
	p.z.Set(q.z)
	return p
}

// SetBytes sets p to the compressed, uncompressed, or infinity value encoded in
// b, as specified in SEC 1, Version 2.0, Section 2.3.4. If the point is not on
// the curve, it returns nil and an error, and the receiver is unchanged.
// Otherwise, it returns p.
func (p *SM2P256Point) SetBytes(b []byte) (*SM2P256Point, error) {
	switch {
	// Point at infinity.
	case len(b) == 1 && b[0] == 0:
		return p.Set(NewSM2P256Point()), nil
	// Uncompressed form.
	case len(b) == 1+2*sm2p256ElementLength && b[0] == 4:
		x, err := new(SM2P256Element).SetBytes(b[1 : 1+sm2p256ElementLength])
		if err != nil {
			return nil, err
		}
		y, err := new(SM2P256Element).SetBytes(b[1+sm2p256ElementLength:])
		if err != nil {
			return nil, err
		}
		if err := sm2p256CheckOnCurve(x, y); err != nil {
			return nil, err
		}
		p.x.Set(x)
		p.y.Set(y)
		p.z.One()
		return p, nil
	// Compressed form.
	case len(b) == 1+sm2p256ElementLength && (b[0] == 2 || b[0] == 3):
		x, err := new(SM2P256Element).SetBytes(b[1:])
		if err != nil {
			return nil, err
		}
		// y² = x³ - 3x + b
		y := sm2p256Polynomial(new(SM2P256Element), x)
		if !sm2p256Sqrt(y, y) {
			return nil, errors.New("invalid SM2P256 compressed point encoding")
		}
		// Select the positive or negative root, as indicated by the least
		// significant bit, based on the encoding type byte.
		otherRoot := new(SM2P256Element)
		otherRoot.Sub(otherRoot, y)
		cond := y.Bytes()[sm2p256ElementLength-1]&1 ^ b[0]&1
		y.Select(otherRoot, y, int(cond))
		p.x.Set(x)
		p.y.Set(y)
		p.z.One()
		return p, nil
	default:
		return nil, errors.New("invalid SM2P256 point encoding")
	}
}

var _sm2p256B *SM2P256Element
var _sm2p256BOnce sync.Once

func sm2p256B() *SM2P256Element {
	_sm2p256BOnce.Do(func() {
		_sm2p256B, _ = new(SM2P256Element).SetBytes([]byte{0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x9, 0xa7, 0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92, 0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0xe, 0x93})
	})
	return _sm2p256B
}

// sm2p256Polynomial sets y2 to x³ - 3x + b, and returns y2.
func sm2p256Polynomial(y2, x *SM2P256Element) *SM2P256Element {
	y2.Square(x)
	y2.Mul(y2, x)

	threeX := new(SM2P256Element).Add(x, x)
	threeX.Add(threeX, x)

	y2.Sub(y2, threeX)

	return y2.Add(y2, sm2p256B())
}

func sm2p256CheckOnCurve(x, y *SM2P256Element) error {
	// y² = x³ - 3x + b
	rhs := sm2p256Polynomial(new(SM2P256Element), x)
	lhs := new(SM2P256Element).Square(y)
	if rhs.Equal(lhs) != 1 {
		return errors.New("point not on SM2 P256 curve")
	}
	return nil
}

// Bytes returns the uncompressed or infinity encoding of p, as specified in
// SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the point at
// infinity is shorter than all other encodings.
func (p *SM2P256Point) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [1 + 2*sm2p256ElementLength]byte
	return p.bytes(&out)
}

func (p *SM2P256Point) bytes(out *[1 + 2*sm2p256ElementLength]byte) []byte {
	if p.z.IsZero() == 1 {
		return append(out[:0], 0)
	}
	zinv := new(SM2P256Element).Invert(p.z)
	x := new(SM2P256Element).Mul(p.x, zinv)
	y := new(SM2P256Element).Mul(p.y, zinv)
	buf := append(out[:0], 4)
	buf = append(buf, x.Bytes()...)
	buf = append(buf, y.Bytes()...)
	return buf
}

// BytesX returns the encoding of the x-coordinate of p, as specified in SEC 1,
// Version 2.0, Section 2.3.5, or an error if p is the point at infinity.
func (p *SM2P256Point) BytesX() ([]byte, error) {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [sm2p256ElementLength]byte
	return p.bytesX(&out)
}

func (p *SM2P256Point) bytesX(out *[sm2p256ElementLength]byte) ([]byte, error) {
	if p.z.IsZero() == 1 {
		return nil, errors.New("SM2P256 point is the point at infinity")
	}
	zinv := new(SM2P256Element).Invert(p.z)
	x := new(SM2P256Element).Mul(p.x, zinv)
	return append(out[:0], x.Bytes()...), nil
}

// BytesCompressed returns the compressed or infinity encoding of p, as
// specified in SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the
// point at infinity is shorter than all other encodings.
func (p *SM2P256Point) BytesCompressed() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [1 + sm2p256ElementLength]byte
	return p.bytesCompressed(&out)
}

func (p *SM2P256Point) bytesCompressed(out *[1 + sm2p256ElementLength]byte) []byte {
	if p.z.IsZero() == 1 {
		return append(out[:0], 0)
	}
	zinv := new(SM2P256Element).Invert(p.z)
	x := new(SM2P256Element).Mul(p.x, zinv)
	y := new(SM2P256Element).Mul(p.y, zinv)
	// Encode the sign of the y coordinate (indicated by the least significant
	// bit) as the encoding type (2 or 3).
	buf := append(out[:0], 2)
	buf[0] |= y.Bytes()[sm2p256ElementLength-1] & 1
	buf = append(buf, x.Bytes()...)
	return buf
}

// Add sets q = p1 + p2, and returns q. The points may overlap.
func (q *SM2P256Point) Add(p1, p2 *SM2P256Point) *SM2P256Point {
	// Complete addition formula for a = -3 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.
	t0 := new(SM2P256Element).Mul(p1.x, p2.x)     // t0 := X1 * X2
	t1 := new(SM2P256Element).Mul(p1.y, p2.y)     // t1 := Y1 * Y2
	t2 := new(SM2P256Element).Mul(p1.z, p2.z)     // t2 := Z1 * Z2
	t3 := new(SM2P256Element).Add(p1.x, p1.y)     // t3 := X1 + Y1
	t4 := new(SM2P256Element).Add(p2.x, p2.y)     // t4 := X2 + Y2
	t3.Mul(t3, t4)                                // t3 := t3 * t4
	t4.Add(t0, t1)                                // t4 := t0 + t1
	t3.Sub(t3, t4)                                // t3 := t3 - t4
	t4.Add(p1.y, p1.z)                            // t4 := Y1 + Z1
	x3 := new(SM2P256Element).Add(p2.y, p2.z)     // X3 := Y2 + Z2
	t4.Mul(t4, x3)                                // t4 := t4 * X3
	x3.Add(t1, t2)                                // X3 := t1 + t2
	t4.Sub(t4, x3)                                // t4 := t4 - X3
	x3.Add(p1.x, p1.z)                            // X3 := X1 + Z1
	y3 := new(SM2P256Element).Add(p2.x, p2.z)     // Y3 := X2 + Z2
	x3.Mul(x3, y3)                                // X3 := X3 * Y3
	y3.Add(t0, t2)                                // Y3 := t0 + t2
	y3.Sub(x3, y3)                                // Y3 := X3 - Y3
	z3 := new(SM2P256Element).Mul(sm2p256B(), t2) // Z3 := b * t2
	x3.Sub(y3, z3)                                // X3 := Y3 - Z3
	z3.Add(x3, x3)                                // Z3 := X3 + X3
	x3.Add(x3, z3)                                // X3 := X3 + Z3
	z3.Sub(t1, x3)                                // Z3 := t1 - X3
	x3.Add(t1, x3)                                // X3 := t1 + X3
	y3.Mul(sm2p256B(), y3)                        // Y3 := b * Y3
	t1.Add(t2, t2)                                // t1 := t2 + t2
	t2.Add(t1, t2)                                // t2 := t1 + t2
	y3.Sub(y3, t2)                                // Y3 := Y3 - t2
	y3.Sub(y3, t0)                                // Y3 := Y3 - t0
	t1.Add(y3, y3)                                // t1 := Y3 + Y3
	y3.Add(t1, y3)                                // Y3 := t1 + Y3
	t1.Add(t0, t0)                                // t1 := t0 + t0
	t0.Add(t1, t0)                                // t0 := t1 + t0
	t0.Sub(t0, t2)                                // t0 := t0 - t2
	t1.Mul(t4, y3)                                // t1 := t4 * Y3
	t2.Mul(t0, y3)                                // t2 := t0 * Y3
	y3.Mul(x3, z3)                                // Y3 := X3 * Z3
	y3.Add(y3, t2)                                // Y3 := Y3 + t2
	x3.Mul(t3, x3)                                // X3 := t3 * X3
	x3.Sub(x3, t1)                                // X3 := X3 - t1
	z3.Mul(t4, z3)                                // Z3 := t4 * Z3
	t1.Mul(t3, t0)                                // t1 := t3 * t0
	z3.Add(z3, t1)                                // Z3 := Z3 + t1

	q.x.Set(x3)
	q.y.Set(y3)
	q.z.Set(z3)
	return q
}

// Double sets q = p + p, and returns q. The points may overlap.
func (q *SM2P256Point) Double(p *SM2P256Point) *SM2P256Point {
	// Complete addition formula for a = -3 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.
	t0 := new(SM2P256Element).Square(p.x)         // t0 := X ^ 2
	t1 := new(SM2P256Element).Square(p.y)         // t1 := Y ^ 2
	t2 := new(SM2P256Element).Square(p.z)         // t2 := Z ^ 2
	t3 := new(SM2P256Element).Mul(p.x, p.y)       // t3 := X * Y
	t3.Add(t3, t3)                                // t3 := t3 + t3
	z3 := new(SM2P256Element).Mul(p.x, p.z)       // Z3 := X * Z
	z3.Add(z3, z3)                                // Z3 := Z3 + Z3
	y3 := new(SM2P256Element).Mul(sm2p256B(), t2) // Y3 := b * t2
	y3.Sub(y3, z3)                                // Y3 := Y3 - Z3
	x3 := new(SM2P256Element).Add(y3, y3)         // X3 := Y3 + Y3
	y3.Add(x3, y3)                                // Y3 := X3 + Y3
	x3.Sub(t1, y3)                                // X3 := t1 - Y3
	y3.Add(t1, y3)                                // Y3 := t1 + Y3
	y3.Mul(x3, y3)                                // Y3 := X3 * Y3
	x3.Mul(x3, t3)                                // X3 := X3 * t3
	t3.Add(t2, t2)                                // t3 := t2 + t2
	t2.Add(t2, t3)                                // t2 := t2 + t3
	z3.Mul(sm2p256B(), z3)                        // Z3 := b * Z3
	z3.Sub(z3, t2)                                // Z3 := Z3 - t2
	z3.Sub(z3, t0)                                // Z3 := Z3 - t0
	t3.Add(z3, z3)                                // t3 := Z3 + Z3
	z3.Add(z3, t3)                                // Z3 := Z3 + t3
	t3.Add(t0, t0)                                // t3 := t0 + t0
	t0.Add(t3, t0)                                // t0 := t3 + t0
	t0.Sub(t0, t2)                                // t0 := t0 - t2
	t0.Mul(t0, z3)                                // t0 := t0 * Z3
	y3.Add(y3, t0)                                // Y3 := Y3 + t0
	t0.Mul(p.y, p.z)                              // t0 := Y * Z
	t0.Add(t0, t0)                                // t0 := t0 + t0
	z3.Mul(t0, z3)                                // Z3 := t0 * Z3
	x3.Sub(x3, z3)                                // X3 := X3 - Z3
	z3.Mul(t0, t1)                                // Z3 := t0 * t1
	z3.Add(z3, z3)                                // Z3 := Z3 + Z3
	z3.Add(z3, z3)                                // Z3 := Z3 + Z3

	q.x.Set(x3)
	q.y.Set(y3)
	q.z.Set(z3)
	return q
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *SM2P256Point) Select(p1, p2 *SM2P256Point, cond int) *SM2P256Point {
	q.x.Select(p1.x, p2.x, cond)
	q.y.Select(p1.y, p2.y, cond)
	q.z.Select(p1.z, p2.z, cond)
	return q
}

// A sm2p256Table holds the first 15 multiples of a point at offset -1, so [1]P
// is at table[0], [15]P is at table[14], and [0]P is implicitly the identity
// point.
type sm2p256Table [15]*SM2P256Point

// Select selects the n-th multiple of the table base point into p. It works in
// constant time by iterating over every entry of the table. n must be in [0, 15].
func (table *sm2p256Table) Select(p *SM2P256Point, n uint8) {
	if n >= 16 {
		panic("sm2ec: internal error: sm2p256Table called with out-of-bounds value")
	}
	p.Set(NewSM2P256Point())
	for i, f := range table {
		cond := subtle.ConstantTimeByteEq(uint8(i+1), n)
		p.Select(f, p, cond)
	}
}

// ScalarMult sets p = scalar * q, and returns p.
func (p *SM2P256Point) ScalarMult(q *SM2P256Point, scalar []byte) (*SM2P256Point, error) {
	// Compute a sm2p256Table for the base point q. The explicit NewSM2P256Point
	// calls get inlined, letting the allocations live on the stack.
	var table = sm2p256Table{NewSM2P256Point(), NewSM2P256Point(), NewSM2P256Point(),
		NewSM2P256Point(), NewSM2P256Point(), NewSM2P256Point(), NewSM2P256Point(),
		NewSM2P256Point(), NewSM2P256Point(), NewSM2P256Point(), NewSM2P256Point(),
		NewSM2P256Point(), NewSM2P256Point(), NewSM2P256Point(), NewSM2P256Point()}
	table[0].Set(q)
	for i := 1; i < 15; i += 2 {
		table[i].Double(table[i/2])
		table[i+1].Add(table[i], q)
	}

	// Instead of doing the classic double-and-add chain, we do it with a
	// four-bit window: we double four times, and then add [0-15]P.
	t := NewSM2P256Point()
	p.Set(NewSM2P256Point())
	for i, byte := range scalar {
		// No need to double on the first iteration, as p is the identity at
		// this point, and [N]∞ = ∞.
		if i != 0 {
			p.Double(p)
			p.Double(p)
			p.Double(p)
			p.Double(p)
		}

		windowValue := byte >> 4
		table.Select(t, windowValue)
		p.Add(p, t)

		p.Double(p)
		p.Double(p)
		p.Double(p)
		p.Double(p)

		windowValue = byte & 0b1111
		table.Select(t, windowValue)
		p.Add(p, t)
	}

	return p, nil
}

var sm2p256GeneratorTable *[sm2p256ElementLength * 2]sm2p256Table
var sm2p256GeneratorTableOnce sync.Once

// generatorTable returns a sequence of sm2p256Tables. The first table contains
// multiples of G. Each successive table is the previous table doubled four
// times.
func (p *SM2P256Point) generatorTable() *[sm2p256ElementLength * 2]sm2p256Table {
	sm2p256GeneratorTableOnce.Do(func() {
		sm2p256GeneratorTable = new([sm2p256ElementLength * 2]sm2p256Table)
		base := NewSM2P256Point().SetGenerator()
		for i := 0; i < sm2p256ElementLength*2; i++ {
			sm2p256GeneratorTable[i][0] = NewSM2P256Point().Set(base)
			for j := 1; j < 15; j++ {
				sm2p256GeneratorTable[i][j] = NewSM2P256Point().Add(sm2p256GeneratorTable[i][j-1], base)
			}
			base.Double(base)
			base.Double(base)
			base.Double(base)
			base.Double(base)
		}
	})
	return sm2p256GeneratorTable
}

// ScalarBaseMult sets p = scalar * B, where B is the canonical generator, and
// returns p.
func (p *SM2P256Point) ScalarBaseMult(scalar []byte) (*SM2P256Point, error) {
	if len(scalar) != sm2p256ElementLength {
		return nil, errors.New("invalid scalar length")
	}
	tables := p.generatorTable()

	// This is also a scalar multiplication with a four-bit window like in
	// ScalarMult, but in this case the doublings are precomputed. The value
	// [windowValue]G added at iteration k would normally get doubled
	// (totIterations-k)×4 times, but with a larger precomputation we can
	// instead add [2^((totIterations-k)×4)][windowValue]G and avoid the
	// doublings between iterations.
	t := NewSM2P256Point()
	p.Set(NewSM2P256Point())
	tableIndex := len(tables) - 1
	for _, byte := range scalar {
		windowValue := byte >> 4
		tables[tableIndex].Select(t, windowValue)
		p.Add(p, t)
		tableIndex--

		windowValue = byte & 0b1111
		tables[tableIndex].Select(t, windowValue)
		p.Add(p, t)
		tableIndex--
	}

	return p, nil
}

// sm2p256Sqrt sets e to a square root of x. If x is not a square, sm2p256Sqrt returns
// false and e is unchanged. e and x can overlap.
func sm2p256Sqrt(e, x *SM2P256Element) (isSquare bool) {
	candidate := new(SM2P256Element)
	sm2p256SqrtCandidate(candidate, x)
	square := new(SM2P256Element).Square(candidate)
	if square.Equal(x) != 1 {
		return false
	}
	e.Set(candidate)
	return true
}

// sm2p256SqrtCandidate sets z to a square root candidate for x. z and x must not overlap.
func sm2p256SqrtCandidate(z, x *SM2P256Element) {
	// Since p = 3 mod 4, exponentiation by (p + 1) / 4 yields a square root candidate.
	//
	// The sequence of 13 multiplications and 253 squarings is derived from the
	// following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
	//
	//	_10      = 2*1
	//	_11      = 1 + _10
	//	_110     = 2*_11
	//	_111     = 1 + _110
	//	_1110    = 2*_111
	//	_1111    = 1 + _1110
	//	_11110   = 2*_1111
	//	_111100  = 2*_11110
	//	_1111000 = 2*_111100
	//	i19      = (_1111000 << 3 + _111100) << 5 + _1111000
	//	x31      = (i19 << 2 + _11110) << 14 + i19 + _111
	//	i42      = x31 << 4
	//	i73      = i42 << 31
	//	i74      = i42 + i73
	//	i171     = (i73 << 32 + i74) << 62 + i74 + _1111
	//	return     (i171 << 32 + 1) << 62
	//
	var t0 = new(SM2P256Element)
	var t1 = new(SM2P256Element)
	var t2 = new(SM2P256Element)
	var t3 = new(SM2P256Element)
	var t4 = new(SM2P256Element)

	z.Square(x)
	z.Mul(x, z)
	z.Square(z)
	t0.Mul(x, z)
	z.Square(t0)
	z.Mul(x, z)
	t2.Square(z)
	t3.Square(t2)
	t1.Square(t3)
	t4.Square(t1)
	for s := 1; s < 3; s++ {
		t4.Square(t4)
	}
	t3.Mul(t3, t4)
	for s := 0; s < 5; s++ {
		t3.Square(t3)
	}
	t1.Mul(t1, t3)
	t3.Square(t1)
	for s := 1; s < 2; s++ {
		t3.Square(t3)
	}
	t2.Mul(t2, t3)
	for s := 0; s < 14; s++ {
		t2.Square(t2)
	}
	t1.Mul(t1, t2)
	t0.Mul(t0, t1)
	for s := 0; s < 4; s++ {
		t0.Square(t0)
	}
	t1.Square(t0)
	for s := 1; s < 31; s++ {
		t1.Square(t1)
	}
	t0.Mul(t0, t1)
	for s := 0; s < 32; s++ {
		t1.Square(t1)
	}
	t1.Mul(t0, t1)
	for s := 0; s < 62; s++ {
		t1.Square(t1)
	}
	t0.Mul(t0, t1)
	z.Mul(z, t0)
	for s := 0; s < 32; s++ {
		z.Square(z)
	}
	z.Mul(x, z)
	for s := 0; s < 62; s++ {
		z.Square(z)
	}
}

// go

// SM2P256Element is an integer modulo 2^256 - 2^224 - 2^96 + 2^64 - 1.
//
// The zero value is a valid zero element.
type SM2P256Element struct {
	// Values are represented internally always in the Montgomery domain, and
	// converted in Bytes and SetBytes.
	x sm2p256MontgomeryDomainFieldElement
}

const sm2p256ElementLen = 32

type sm2p256UntypedFieldElement = [4]uint64

// One sets e = 1, and returns e.
func (e *SM2P256Element) One() *SM2P256Element {
	sm2p256SetOne(&e.x)
	return e
}

// Equal returns 1 if e == t, and zero otherwise.
func (e *SM2P256Element) Equal(t *SM2P256Element) int {
	eBytes := e.Bytes()
	tBytes := t.Bytes()
	return subtle.ConstantTimeCompare(eBytes, tBytes)
}

// IsZero returns 1 if e == 0, and zero otherwise.
func (e *SM2P256Element) IsZero() int {
	zero := make([]byte, sm2p256ElementLen)
	eBytes := e.Bytes()
	return subtle.ConstantTimeCompare(eBytes, zero)
}

// Set sets e = t, and returns e.
func (e *SM2P256Element) Set(t *SM2P256Element) *SM2P256Element {
	e.x = t.x
	return e
}

// Bytes returns the 32-byte big-endian encoding of e.
func (e *SM2P256Element) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [sm2p256ElementLen]byte
	return e.bytes(&out)
}

func (e *SM2P256Element) bytes(out *[sm2p256ElementLen]byte) []byte {
	var tmp sm2p256NonMontgomeryDomainFieldElement
	sm2p256FromMontgomery(&tmp, &e.x)
	sm2p256ToBytes(out, (*sm2p256UntypedFieldElement)(&tmp))
	sm2p256InvertEndianness(out[:])
	return out[:]
}

// SetBytes sets e = v, where v is a big-endian 32-byte encoding, and returns e.
// If v is not 32 bytes or it encodes a value higher than 2^256 - 2^224 - 2^96 + 2^64 - 1,
// SetBytes returns nil and an error, and e is unchanged.
func (e *SM2P256Element) SetBytes(v []byte) (*SM2P256Element, error) {
	if len(v) != sm2p256ElementLen {
		return nil, errors.New("invalid SM2P256Element encoding")
	}

	// Check for non-canonical encodings (p + k, 2p + k, etc.) by comparing to
	// the encoding of -1 mod p, so p - 1, the highest canonical encoding.
	var minusOneEncoding = new(SM2P256Element).Sub(
		new(SM2P256Element), new(SM2P256Element).One()).Bytes()
	for i := range v {
		if v[i] < minusOneEncoding[i] {
			break
		}
		if v[i] > minusOneEncoding[i] {
			return nil, errors.New("invalid SM2P256Element encoding")
		}
	}

	var in [sm2p256ElementLen]byte
	copy(in[:], v)
	sm2p256InvertEndianness(in[:])
	var tmp sm2p256NonMontgomeryDomainFieldElement
	sm2p256FromBytes((*sm2p256UntypedFieldElement)(&tmp), &in)
	sm2p256ToMontgomery(&e.x, &tmp)
	return e, nil
}

// Add sets e = t1 + t2, and returns e.
func (e *SM2P256Element) Add(t1, t2 *SM2P256Element) *SM2P256Element {
	sm2p256Add(&e.x, &t1.x, &t2.x)
	return e
}

// Sub sets e = t1 - t2, and returns e.
func (e *SM2P256Element) Sub(t1, t2 *SM2P256Element) *SM2P256Element {
	sm2p256Sub(&e.x, &t1.x, &t2.x)
	return e
}

// Mul sets e = t1 * t2, and returns e.
func (e *SM2P256Element) Mul(t1, t2 *SM2P256Element) *SM2P256Element {
	sm2p256Mul(&e.x, &t1.x, &t2.x)
	return e
}

// Square sets e = t * t, and returns e.
func (e *SM2P256Element) Square(t *SM2P256Element) *SM2P256Element {
	sm2p256Square(&e.x, &t.x)
	return e
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *SM2P256Element) Select(a, b *SM2P256Element, cond int) *SM2P256Element {
	sm2p256Selectznz((*sm2p256UntypedFieldElement)(&v.x), sm2p256Uint1(cond),
		(*sm2p256UntypedFieldElement)(&b.x), (*sm2p256UntypedFieldElement)(&a.x))
	return v
}

func sm2p256InvertEndianness(v []byte) {
	for i := 0; i < len(v)/2; i++ {
		v[i], v[len(v)-1-i] = v[len(v)-1-i], v[i]
	}
}

var orderK0 uint64 = 0x327f9e8872350975

// SM2P256OrderElement is an integer modulo 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123.
//
// The zero value is a valid zero element.
type SM2P256OrderElement struct {
	// Values are represented internally always in the Montgomery domain, and
	// converted in Bytes and SetBytes.
	x sm2p256MontgomeryDomainFieldElement
}

// One sets e = 1, and returns e.
func (e *SM2P256OrderElement) One() *SM2P256OrderElement {
	e.x[0] = 0xac440bf6c62abedd
	e.x[1] = 0x8dfc2094de39fad4
	e.x[2] = uint64(0x0)
	e.x[3] = 0x100000000
	return e
}

// Add sets e = t1 + t2, and returns e.
func (e *SM2P256OrderElement) Add(t1, t2 *SM2P256OrderElement) *SM2P256OrderElement {
	var x1 uint64
	var x2 uint64
	x1, x2 = bits.Add64(t1.x[0], t2.x[0], uint64(0x0))
	var x3 uint64
	var x4 uint64
	x3, x4 = bits.Add64(t1.x[1], t2.x[1], uint64(sm2p256Uint1(x2)))
	var x5 uint64
	var x6 uint64
	x5, x6 = bits.Add64(t1.x[2], t2.x[2], uint64(sm2p256Uint1(x4)))
	var x7 uint64
	var x8 uint64
	x7, x8 = bits.Add64(t1.x[3], t2.x[3], uint64(sm2p256Uint1(x6)))
	var x9 uint64
	var x10 uint64
	x9, x10 = bits.Sub64(x1, 0x53bbf40939d54123, uint64(0x0))
	var x11 uint64
	var x12 uint64
	x11, x12 = bits.Sub64(x3, 0x7203df6b21c6052b, uint64(sm2p256Uint1(x10)))
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Sub64(x5, 0xffffffffffffffff, uint64(sm2p256Uint1(x12)))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Sub64(x7, 0xfffffffeffffffff, uint64(sm2p256Uint1(x14)))
	var x18 uint64
	_, x18 = bits.Sub64(uint64(sm2p256Uint1(x8)), uint64(0x0), uint64(sm2p256Uint1(x16)))
	var x19 uint64
	sm2p256CmovznzU64(&x19, sm2p256Uint1(x18), x9, x1)
	var x20 uint64
	sm2p256CmovznzU64(&x20, sm2p256Uint1(x18), x11, x3)
	var x21 uint64
	sm2p256CmovznzU64(&x21, sm2p256Uint1(x18), x13, x5)
	var x22 uint64
	sm2p256CmovznzU64(&x22, sm2p256Uint1(x18), x15, x7)
	e.x[0] = x19
	e.x[1] = x20
	e.x[2] = x21
	e.x[3] = x22
	return e
}

// Sub sets e = t1 - t2, and returns e.
func (e *SM2P256OrderElement) Sub(t1, t2 *SM2P256OrderElement) *SM2P256OrderElement {
	var x1 uint64
	var x2 uint64
	x1, x2 = bits.Sub64(t1.x[0], t2.x[0], uint64(0x0))
	var x3 uint64
	var x4 uint64
	x3, x4 = bits.Sub64(t1.x[1], t2.x[1], uint64(sm2p256Uint1(x2)))
	var x5 uint64
	var x6 uint64
	x5, x6 = bits.Sub64(t1.x[2], t2.x[2], uint64(sm2p256Uint1(x4)))
	var x7 uint64
	var x8 uint64
	x7, x8 = bits.Sub64(t1.x[3], t2.x[3], uint64(sm2p256Uint1(x6)))
	var x9 uint64
	sm2p256CmovznzU64(&x9, sm2p256Uint1(x8), uint64(0x0), 0xffffffffffffffff)
	var x10 uint64
	var x11 uint64
	x10, x11 = bits.Add64(x1, (x9 & 0x53bbf40939d54123), uint64(0x0))
	var x12 uint64
	var x13 uint64
	x12, x13 = bits.Add64(x3, (x9 & 0x7203df6b21c6052b), uint64(sm2p256Uint1(x11)))
	var x14 uint64
	var x15 uint64
	x14, x15 = bits.Add64(x5, x9, uint64(sm2p256Uint1(x13)))
	var x16 uint64
	x16, _ = bits.Add64(x7, (x9 & 0xfffffffeffffffff), uint64(sm2p256Uint1(x15)))
	e.x[0] = x10
	e.x[1] = x12
	e.x[2] = x14
	e.x[3] = x16
	return e
}

// Mul sets e = t1 * t2, and returns e.
func (e *SM2P256OrderElement) Mul(t1, t2 *SM2P256OrderElement) *SM2P256OrderElement {
	x1 := t1.x[1]
	x2 := t1.x[2]
	x3 := t1.x[3]
	x4 := t1.x[0]
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x4, t2.x[3])
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x4, t2.x[2])
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x4, t2.x[1])
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x4, t2.x[0])
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Add64(x12, x9, uint64(0x0))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Add64(x10, x7, uint64(sm2p256Uint1(x14)))
	var x17 uint64
	var x18 uint64
	x17, x18 = bits.Add64(x8, x5, uint64(sm2p256Uint1(x16)))
	x19 := (uint64(sm2p256Uint1(x18)) + x6)
	var x20 uint64
	var x21 uint64
	_, y11 := bits.Mul64(x11, orderK0)
	x21, x20 = bits.Mul64(y11, 0xfffffffeffffffff)
	var x22 uint64
	var x23 uint64
	x23, x22 = bits.Mul64(y11, 0xffffffffffffffff)
	var x24 uint64
	var x25 uint64
	x25, x24 = bits.Mul64(y11, 0x7203df6b21c6052b)
	var x26 uint64
	var x27 uint64
	x27, x26 = bits.Mul64(y11, 0x53bbf40939d54123)
	var x28 uint64
	var x29 uint64
	x28, x29 = bits.Add64(x27, x24, uint64(0x0))
	var x30 uint64
	var x31 uint64
	x30, x31 = bits.Add64(x25, x22, uint64(sm2p256Uint1(x29)))
	var x32 uint64
	var x33 uint64
	x32, x33 = bits.Add64(x23, x20, uint64(sm2p256Uint1(x31)))
	x34 := (uint64(sm2p256Uint1(x33)) + x21)
	var x36 uint64
	_, x36 = bits.Add64(x11, x26, uint64(0x0))
	var x37 uint64
	var x38 uint64
	x37, x38 = bits.Add64(x13, x28, uint64(sm2p256Uint1(x36)))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x15, x30, uint64(sm2p256Uint1(x38)))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64(x17, x32, uint64(sm2p256Uint1(x40)))
	var x43 uint64
	var x44 uint64
	x43, x44 = bits.Add64(x19, x34, uint64(sm2p256Uint1(x42)))
	var x45 uint64
	var x46 uint64
	x46, x45 = bits.Mul64(x1, t2.x[3])
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(x1, t2.x[2])
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(x1, t2.x[1])
	var x51 uint64
	var x52 uint64
	x52, x51 = bits.Mul64(x1, t2.x[0])
	var x53 uint64
	var x54 uint64
	x53, x54 = bits.Add64(x52, x49, uint64(0x0))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x50, x47, uint64(sm2p256Uint1(x54)))
	var x57 uint64
	var x58 uint64
	x57, x58 = bits.Add64(x48, x45, uint64(sm2p256Uint1(x56)))
	x59 := (uint64(sm2p256Uint1(x58)) + x46)
	var x60 uint64
	var x61 uint64
	x60, x61 = bits.Add64(x37, x51, uint64(0x0))
	var x62 uint64
	var x63 uint64
	x62, x63 = bits.Add64(x39, x53, uint64(sm2p256Uint1(x61)))
	var x64 uint64
	var x65 uint64
	x64, x65 = bits.Add64(x41, x55, uint64(sm2p256Uint1(x63)))
	var x66 uint64
	var x67 uint64
	x66, x67 = bits.Add64(x43, x57, uint64(sm2p256Uint1(x65)))
	var x68 uint64
	var x69 uint64
	x68, x69 = bits.Add64(uint64(sm2p256Uint1(x44)), x59, uint64(sm2p256Uint1(x67)))
	var x70 uint64
	var x71 uint64
	_, y60 := bits.Mul64(x60, orderK0)
	x71, x70 = bits.Mul64(y60, 0xfffffffeffffffff)
	var x72 uint64
	var x73 uint64
	x73, x72 = bits.Mul64(y60, 0xffffffffffffffff)
	var x74 uint64
	var x75 uint64
	x75, x74 = bits.Mul64(y60, 0x7203df6b21c6052b)
	var x76 uint64
	var x77 uint64
	x77, x76 = bits.Mul64(y60, 0x53bbf40939d54123)
	var x78 uint64
	var x79 uint64
	x78, x79 = bits.Add64(x77, x74, uint64(0x0))
	var x80 uint64
	var x81 uint64
	x80, x81 = bits.Add64(x75, x72, uint64(sm2p256Uint1(x79)))
	var x82 uint64
	var x83 uint64
	x82, x83 = bits.Add64(x73, x70, uint64(sm2p256Uint1(x81)))
	x84 := (uint64(sm2p256Uint1(x83)) + x71)
	var x86 uint64
	_, x86 = bits.Add64(x60, x76, uint64(0x0))
	var x87 uint64
	var x88 uint64
	x87, x88 = bits.Add64(x62, x78, uint64(sm2p256Uint1(x86)))
	var x89 uint64
	var x90 uint64
	x89, x90 = bits.Add64(x64, x80, uint64(sm2p256Uint1(x88)))
	var x91 uint64
	var x92 uint64
	x91, x92 = bits.Add64(x66, x82, uint64(sm2p256Uint1(x90)))
	var x93 uint64
	var x94 uint64
	x93, x94 = bits.Add64(x68, x84, uint64(sm2p256Uint1(x92)))
	x95 := (uint64(sm2p256Uint1(x94)) + uint64(sm2p256Uint1(x69)))
	var x96 uint64
	var x97 uint64
	x97, x96 = bits.Mul64(x2, t2.x[3])
	var x98 uint64
	var x99 uint64
	x99, x98 = bits.Mul64(x2, t2.x[2])
	var x100 uint64
	var x101 uint64
	x101, x100 = bits.Mul64(x2, t2.x[1])
	var x102 uint64
	var x103 uint64
	x103, x102 = bits.Mul64(x2, t2.x[0])
	var x104 uint64
	var x105 uint64
	x104, x105 = bits.Add64(x103, x100, uint64(0x0))
	var x106 uint64
	var x107 uint64
	x106, x107 = bits.Add64(x101, x98, uint64(sm2p256Uint1(x105)))
	var x108 uint64
	var x109 uint64
	x108, x109 = bits.Add64(x99, x96, uint64(sm2p256Uint1(x107)))
	x110 := (uint64(sm2p256Uint1(x109)) + x97)
	var x111 uint64
	var x112 uint64
	x111, x112 = bits.Add64(x87, x102, uint64(0x0))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Add64(x89, x104, uint64(sm2p256Uint1(x112)))
	var x115 uint64
	var x116 uint64
	x115, x116 = bits.Add64(x91, x106, uint64(sm2p256Uint1(x114)))
	var x117 uint64
	var x118 uint64
	x117, x118 = bits.Add64(x93, x108, uint64(sm2p256Uint1(x116)))
	var x119 uint64
	var x120 uint64
	x119, x120 = bits.Add64(x95, x110, uint64(sm2p256Uint1(x118)))
	var x121 uint64
	var x122 uint64
	_, y111 := bits.Mul64(x111, orderK0)
	x122, x121 = bits.Mul64(y111, 0xfffffffeffffffff)
	var x123 uint64
	var x124 uint64
	x124, x123 = bits.Mul64(y111, 0xffffffffffffffff)
	var x125 uint64
	var x126 uint64
	x126, x125 = bits.Mul64(y111, 0x7203df6b21c6052b)
	var x127 uint64
	var x128 uint64
	x128, x127 = bits.Mul64(y111, 0x53bbf40939d54123)
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x128, x125, uint64(0x0))
	var x131 uint64
	var x132 uint64
	x131, x132 = bits.Add64(x126, x123, uint64(sm2p256Uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(x124, x121, uint64(sm2p256Uint1(x132)))
	x135 := (uint64(sm2p256Uint1(x134)) + x122)
	var x137 uint64
	_, x137 = bits.Add64(x111, x127, uint64(0x0))
	var x138 uint64
	var x139 uint64
	x138, x139 = bits.Add64(x113, x129, uint64(sm2p256Uint1(x137)))
	var x140 uint64
	var x141 uint64
	x140, x141 = bits.Add64(x115, x131, uint64(sm2p256Uint1(x139)))
	var x142 uint64
	var x143 uint64
	x142, x143 = bits.Add64(x117, x133, uint64(sm2p256Uint1(x141)))
	var x144 uint64
	var x145 uint64
	x144, x145 = bits.Add64(x119, x135, uint64(sm2p256Uint1(x143)))
	x146 := (uint64(sm2p256Uint1(x145)) + uint64(sm2p256Uint1(x120)))
	var x147 uint64
	var x148 uint64
	x148, x147 = bits.Mul64(x3, t2.x[3])
	var x149 uint64
	var x150 uint64
	x150, x149 = bits.Mul64(x3, t2.x[2])
	var x151 uint64
	var x152 uint64
	x152, x151 = bits.Mul64(x3, t2.x[1])
	var x153 uint64
	var x154 uint64
	x154, x153 = bits.Mul64(x3, t2.x[0])
	var x155 uint64
	var x156 uint64
	x155, x156 = bits.Add64(x154, x151, uint64(0x0))
	var x157 uint64
	var x158 uint64
	x157, x158 = bits.Add64(x152, x149, uint64(sm2p256Uint1(x156)))
	var x159 uint64
	var x160 uint64
	x159, x160 = bits.Add64(x150, x147, uint64(sm2p256Uint1(x158)))
	x161 := (uint64(sm2p256Uint1(x160)) + x148)
	var x162 uint64
	var x163 uint64
	x162, x163 = bits.Add64(x138, x153, uint64(0x0))
	var x164 uint64
	var x165 uint64
	x164, x165 = bits.Add64(x140, x155, uint64(sm2p256Uint1(x163)))
	var x166 uint64
	var x167 uint64
	x166, x167 = bits.Add64(x142, x157, uint64(sm2p256Uint1(x165)))
	var x168 uint64
	var x169 uint64
	x168, x169 = bits.Add64(x144, x159, uint64(sm2p256Uint1(x167)))
	var x170 uint64
	var x171 uint64
	x170, x171 = bits.Add64(x146, x161, uint64(sm2p256Uint1(x169)))
	var x172 uint64
	var x173 uint64
	_, y162 := bits.Mul64(x162, orderK0)
	x173, x172 = bits.Mul64(y162, 0xfffffffeffffffff)
	var x174 uint64
	var x175 uint64
	x175, x174 = bits.Mul64(y162, 0xffffffffffffffff)
	var x176 uint64
	var x177 uint64
	x177, x176 = bits.Mul64(y162, 0x7203df6b21c6052b)
	var x178 uint64
	var x179 uint64
	x179, x178 = bits.Mul64(y162, 0x53bbf40939d54123)
	var x180 uint64
	var x181 uint64
	x180, x181 = bits.Add64(x179, x176, uint64(0x0))
	var x182 uint64
	var x183 uint64
	x182, x183 = bits.Add64(x177, x174, uint64(sm2p256Uint1(x181)))
	var x184 uint64
	var x185 uint64
	x184, x185 = bits.Add64(x175, x172, uint64(sm2p256Uint1(x183)))
	x186 := (uint64(sm2p256Uint1(x185)) + x173)
	var x188 uint64
	_, x188 = bits.Add64(x162, x178, uint64(0x0))
	var x189 uint64
	var x190 uint64
	x189, x190 = bits.Add64(x164, x180, uint64(sm2p256Uint1(x188)))
	var x191 uint64
	var x192 uint64
	x191, x192 = bits.Add64(x166, x182, uint64(sm2p256Uint1(x190)))
	var x193 uint64
	var x194 uint64
	x193, x194 = bits.Add64(x168, x184, uint64(sm2p256Uint1(x192)))
	var x195 uint64
	var x196 uint64
	x195, x196 = bits.Add64(x170, x186, uint64(sm2p256Uint1(x194)))
	x197 := (uint64(sm2p256Uint1(x196)) + uint64(sm2p256Uint1(x171)))
	var x198 uint64
	var x199 uint64
	x198, x199 = bits.Sub64(x189, 0x53bbf40939d54123, uint64(0x0))
	var x200 uint64
	var x201 uint64
	x200, x201 = bits.Sub64(x191, 0x7203df6b21c6052b, uint64(sm2p256Uint1(x199)))
	var x202 uint64
	var x203 uint64
	x202, x203 = bits.Sub64(x193, 0xffffffffffffffff, uint64(sm2p256Uint1(x201)))
	var x204 uint64
	var x205 uint64
	x204, x205 = bits.Sub64(x195, 0xfffffffeffffffff, uint64(sm2p256Uint1(x203)))
	var x207 uint64
	_, x207 = bits.Sub64(x197, uint64(0x0), uint64(sm2p256Uint1(x205)))
	var x208 uint64
	sm2p256CmovznzU64(&x208, sm2p256Uint1(x207), x198, x189)
	var x209 uint64
	sm2p256CmovznzU64(&x209, sm2p256Uint1(x207), x200, x191)
	var x210 uint64
	sm2p256CmovznzU64(&x210, sm2p256Uint1(x207), x202, x193)
	var x211 uint64
	sm2p256CmovznzU64(&x211, sm2p256Uint1(x207), x204, x195)
	e.x[0] = x208
	e.x[1] = x209
	e.x[2] = x210
	e.x[3] = x211

	return e
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *SM2P256OrderElement) Select(a, b *SM2P256OrderElement, cond int) *SM2P256OrderElement {
	sm2p256Selectznz((*sm2p256UntypedFieldElement)(&v.x), sm2p256Uint1(cond),
		(*sm2p256UntypedFieldElement)(&b.x), (*sm2p256UntypedFieldElement)(&a.x))
	return v
}

// Square sets e = t * t, and returns e.
func (e *SM2P256OrderElement) Square(t *SM2P256OrderElement) *SM2P256OrderElement {
	x1 := t.x[1]
	x2 := t.x[2]
	x3 := t.x[3]
	x4 := t.x[0]
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x4, t.x[3])
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x4, t.x[2])
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x4, t.x[1])
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x4, t.x[0])
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Add64(x12, x9, uint64(0x0))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Add64(x10, x7, uint64(sm2p256Uint1(x14)))
	var x17 uint64
	var x18 uint64
	x17, x18 = bits.Add64(x8, x5, uint64(sm2p256Uint1(x16)))
	x19 := (uint64(sm2p256Uint1(x18)) + x6)
	var x20 uint64
	var x21 uint64
	_, y11 := bits.Mul64(x11, orderK0)
	x21, x20 = bits.Mul64(y11, 0xfffffffeffffffff)
	var x22 uint64
	var x23 uint64
	x23, x22 = bits.Mul64(y11, 0xffffffffffffffff)
	var x24 uint64
	var x25 uint64
	x25, x24 = bits.Mul64(y11, 0x7203df6b21c6052b)
	var x26 uint64
	var x27 uint64
	x27, x26 = bits.Mul64(y11, 0x53bbf40939d54123)
	var x28 uint64
	var x29 uint64
	x28, x29 = bits.Add64(x27, x24, uint64(0x0))
	var x30 uint64
	var x31 uint64
	x30, x31 = bits.Add64(x25, x22, uint64(sm2p256Uint1(x29)))
	var x32 uint64
	var x33 uint64
	x32, x33 = bits.Add64(x23, x20, uint64(sm2p256Uint1(x31)))
	x34 := (uint64(sm2p256Uint1(x33)) + x21)
	var x36 uint64
	_, x36 = bits.Add64(x11, x26, uint64(0x0))
	var x37 uint64
	var x38 uint64
	x37, x38 = bits.Add64(x13, x28, uint64(sm2p256Uint1(x36)))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x15, x30, uint64(sm2p256Uint1(x38)))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64(x17, x32, uint64(sm2p256Uint1(x40)))
	var x43 uint64
	var x44 uint64
	x43, x44 = bits.Add64(x19, x34, uint64(sm2p256Uint1(x42)))
	var x45 uint64
	var x46 uint64
	x46, x45 = bits.Mul64(x1, t.x[3])
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(x1, t.x[2])
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(x1, t.x[1])
	var x51 uint64
	var x52 uint64
	x52, x51 = bits.Mul64(x1, t.x[0])
	var x53 uint64
	var x54 uint64
	x53, x54 = bits.Add64(x52, x49, uint64(0x0))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x50, x47, uint64(sm2p256Uint1(x54)))
	var x57 uint64
	var x58 uint64
	x57, x58 = bits.Add64(x48, x45, uint64(sm2p256Uint1(x56)))
	x59 := (uint64(sm2p256Uint1(x58)) + x46)
	var x60 uint64
	var x61 uint64
	x60, x61 = bits.Add64(x37, x51, uint64(0x0))
	var x62 uint64
	var x63 uint64
	x62, x63 = bits.Add64(x39, x53, uint64(sm2p256Uint1(x61)))
	var x64 uint64
	var x65 uint64
	x64, x65 = bits.Add64(x41, x55, uint64(sm2p256Uint1(x63)))
	var x66 uint64
	var x67 uint64
	x66, x67 = bits.Add64(x43, x57, uint64(sm2p256Uint1(x65)))
	var x68 uint64
	var x69 uint64
	x68, x69 = bits.Add64(uint64(sm2p256Uint1(x44)), x59, uint64(sm2p256Uint1(x67)))
	var x70 uint64
	var x71 uint64
	_, y60 := bits.Mul64(x60, orderK0)
	x71, x70 = bits.Mul64(y60, 0xfffffffeffffffff)
	var x72 uint64
	var x73 uint64
	x73, x72 = bits.Mul64(y60, 0xffffffffffffffff)
	var x74 uint64
	var x75 uint64
	x75, x74 = bits.Mul64(y60, 0x7203df6b21c6052b)
	var x76 uint64
	var x77 uint64
	x77, x76 = bits.Mul64(y60, 0x53bbf40939d54123)
	var x78 uint64
	var x79 uint64
	x78, x79 = bits.Add64(x77, x74, uint64(0x0))
	var x80 uint64
	var x81 uint64
	x80, x81 = bits.Add64(x75, x72, uint64(sm2p256Uint1(x79)))
	var x82 uint64
	var x83 uint64
	x82, x83 = bits.Add64(x73, x70, uint64(sm2p256Uint1(x81)))
	x84 := (uint64(sm2p256Uint1(x83)) + x71)
	var x86 uint64
	_, x86 = bits.Add64(x60, x76, uint64(0x0))
	var x87 uint64
	var x88 uint64
	x87, x88 = bits.Add64(x62, x78, uint64(sm2p256Uint1(x86)))
	var x89 uint64
	var x90 uint64
	x89, x90 = bits.Add64(x64, x80, uint64(sm2p256Uint1(x88)))
	var x91 uint64
	var x92 uint64
	x91, x92 = bits.Add64(x66, x82, uint64(sm2p256Uint1(x90)))
	var x93 uint64
	var x94 uint64
	x93, x94 = bits.Add64(x68, x84, uint64(sm2p256Uint1(x92)))
	x95 := (uint64(sm2p256Uint1(x94)) + uint64(sm2p256Uint1(x69)))
	var x96 uint64
	var x97 uint64
	x97, x96 = bits.Mul64(x2, t.x[3])
	var x98 uint64
	var x99 uint64
	x99, x98 = bits.Mul64(x2, t.x[2])
	var x100 uint64
	var x101 uint64
	x101, x100 = bits.Mul64(x2, t.x[1])
	var x102 uint64
	var x103 uint64
	x103, x102 = bits.Mul64(x2, t.x[0])
	var x104 uint64
	var x105 uint64
	x104, x105 = bits.Add64(x103, x100, uint64(0x0))
	var x106 uint64
	var x107 uint64
	x106, x107 = bits.Add64(x101, x98, uint64(sm2p256Uint1(x105)))
	var x108 uint64
	var x109 uint64
	x108, x109 = bits.Add64(x99, x96, uint64(sm2p256Uint1(x107)))
	x110 := (uint64(sm2p256Uint1(x109)) + x97)
	var x111 uint64
	var x112 uint64
	x111, x112 = bits.Add64(x87, x102, uint64(0x0))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Add64(x89, x104, uint64(sm2p256Uint1(x112)))
	var x115 uint64
	var x116 uint64
	x115, x116 = bits.Add64(x91, x106, uint64(sm2p256Uint1(x114)))
	var x117 uint64
	var x118 uint64
	x117, x118 = bits.Add64(x93, x108, uint64(sm2p256Uint1(x116)))
	var x119 uint64
	var x120 uint64
	x119, x120 = bits.Add64(x95, x110, uint64(sm2p256Uint1(x118)))
	var x121 uint64
	var x122 uint64
	_, y111 := bits.Mul64(x111, orderK0)
	x122, x121 = bits.Mul64(y111, 0xfffffffeffffffff)
	var x123 uint64
	var x124 uint64
	x124, x123 = bits.Mul64(y111, 0xffffffffffffffff)
	var x125 uint64
	var x126 uint64
	x126, x125 = bits.Mul64(y111, 0x7203df6b21c6052b)
	var x127 uint64
	var x128 uint64
	x128, x127 = bits.Mul64(y111, 0x53bbf40939d54123)
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x128, x125, uint64(0x0))
	var x131 uint64
	var x132 uint64
	x131, x132 = bits.Add64(x126, x123, uint64(sm2p256Uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(x124, x121, uint64(sm2p256Uint1(x132)))
	x135 := (uint64(sm2p256Uint1(x134)) + x122)
	var x137 uint64
	_, x137 = bits.Add64(x111, x127, uint64(0x0))
	var x138 uint64
	var x139 uint64
	x138, x139 = bits.Add64(x113, x129, uint64(sm2p256Uint1(x137)))
	var x140 uint64
	var x141 uint64
	x140, x141 = bits.Add64(x115, x131, uint64(sm2p256Uint1(x139)))
	var x142 uint64
	var x143 uint64
	x142, x143 = bits.Add64(x117, x133, uint64(sm2p256Uint1(x141)))
	var x144 uint64
	var x145 uint64
	x144, x145 = bits.Add64(x119, x135, uint64(sm2p256Uint1(x143)))
	x146 := (uint64(sm2p256Uint1(x145)) + uint64(sm2p256Uint1(x120)))
	var x147 uint64
	var x148 uint64
	x148, x147 = bits.Mul64(x3, t.x[3])
	var x149 uint64
	var x150 uint64
	x150, x149 = bits.Mul64(x3, t.x[2])
	var x151 uint64
	var x152 uint64
	x152, x151 = bits.Mul64(x3, t.x[1])
	var x153 uint64
	var x154 uint64
	x154, x153 = bits.Mul64(x3, t.x[0])
	var x155 uint64
	var x156 uint64
	x155, x156 = bits.Add64(x154, x151, uint64(0x0))
	var x157 uint64
	var x158 uint64
	x157, x158 = bits.Add64(x152, x149, uint64(sm2p256Uint1(x156)))
	var x159 uint64
	var x160 uint64
	x159, x160 = bits.Add64(x150, x147, uint64(sm2p256Uint1(x158)))
	x161 := (uint64(sm2p256Uint1(x160)) + x148)
	var x162 uint64
	var x163 uint64
	x162, x163 = bits.Add64(x138, x153, uint64(0x0))
	var x164 uint64
	var x165 uint64
	x164, x165 = bits.Add64(x140, x155, uint64(sm2p256Uint1(x163)))
	var x166 uint64
	var x167 uint64
	x166, x167 = bits.Add64(x142, x157, uint64(sm2p256Uint1(x165)))
	var x168 uint64
	var x169 uint64
	x168, x169 = bits.Add64(x144, x159, uint64(sm2p256Uint1(x167)))
	var x170 uint64
	var x171 uint64
	x170, x171 = bits.Add64(x146, x161, uint64(sm2p256Uint1(x169)))
	var x172 uint64
	var x173 uint64
	_, y162 := bits.Mul64(x162, orderK0)
	x173, x172 = bits.Mul64(y162, 0xfffffffeffffffff)
	var x174 uint64
	var x175 uint64
	x175, x174 = bits.Mul64(y162, 0xffffffffffffffff)
	var x176 uint64
	var x177 uint64
	x177, x176 = bits.Mul64(y162, 0x7203df6b21c6052b)
	var x178 uint64
	var x179 uint64
	x179, x178 = bits.Mul64(y162, 0x53bbf40939d54123)
	var x180 uint64
	var x181 uint64
	x180, x181 = bits.Add64(x179, x176, uint64(0x0))
	var x182 uint64
	var x183 uint64
	x182, x183 = bits.Add64(x177, x174, uint64(sm2p256Uint1(x181)))
	var x184 uint64
	var x185 uint64
	x184, x185 = bits.Add64(x175, x172, uint64(sm2p256Uint1(x183)))
	x186 := (uint64(sm2p256Uint1(x185)) + x173)
	var x188 uint64
	_, x188 = bits.Add64(x162, x178, uint64(0x0))
	var x189 uint64
	var x190 uint64
	x189, x190 = bits.Add64(x164, x180, uint64(sm2p256Uint1(x188)))
	var x191 uint64
	var x192 uint64
	x191, x192 = bits.Add64(x166, x182, uint64(sm2p256Uint1(x190)))
	var x193 uint64
	var x194 uint64
	x193, x194 = bits.Add64(x168, x184, uint64(sm2p256Uint1(x192)))
	var x195 uint64
	var x196 uint64
	x195, x196 = bits.Add64(x170, x186, uint64(sm2p256Uint1(x194)))
	x197 := (uint64(sm2p256Uint1(x196)) + uint64(sm2p256Uint1(x171)))
	var x198 uint64
	var x199 uint64
	x198, x199 = bits.Sub64(x189, 0x53bbf40939d54123, uint64(0x0))
	var x200 uint64
	var x201 uint64
	x200, x201 = bits.Sub64(x191, 0x7203df6b21c6052b, uint64(sm2p256Uint1(x199)))
	var x202 uint64
	var x203 uint64
	x202, x203 = bits.Sub64(x193, 0xffffffffffffffff, uint64(sm2p256Uint1(x201)))
	var x204 uint64
	var x205 uint64
	x204, x205 = bits.Sub64(x195, 0xfffffffeffffffff, uint64(sm2p256Uint1(x203)))
	var x207 uint64
	_, x207 = bits.Sub64(x197, uint64(0x0), uint64(sm2p256Uint1(x205)))
	var x208 uint64
	sm2p256CmovznzU64(&x208, sm2p256Uint1(x207), x198, x189)
	var x209 uint64
	sm2p256CmovznzU64(&x209, sm2p256Uint1(x207), x200, x191)
	var x210 uint64
	sm2p256CmovznzU64(&x210, sm2p256Uint1(x207), x202, x193)
	var x211 uint64
	sm2p256CmovznzU64(&x211, sm2p256Uint1(x207), x204, x195)
	e.x[0] = x208
	e.x[1] = x209
	e.x[2] = x210
	e.x[3] = x211

	return e
}

// SetBytes sets e = v, where v is a big-endian 32-byte encoding, and returns e.
// If v is not 32 bytes or it encodes a value higher than 2^256 - 2^224 - 2^96 + 2^64 - 1,
// SetBytes returns nil and an error, and e is unchanged.
func (e *SM2P256OrderElement) SetBytes(v []byte) (*SM2P256OrderElement, error) {
	if len(v) != sm2p256ElementLen {
		return nil, errors.New("invalid SM2P256OrderElement encoding")
	}
	/*
		// Check for non-canonical encodings (p + k, 2p + k, etc.) by comparing to
		// the encoding of -1 mod p, so p - 1, the highest canonical encoding.
		var minusOneEncoding = new(SM2P256OrderElement).Sub(
			new(SM2P256OrderElement), new(SM2P256OrderElement).One()).Bytes()
		for i := range v {
			if v[i] < minusOneEncoding[i] {
				break
			}
			if v[i] > minusOneEncoding[i] {
				return nil, errors.New("invalid SM2P256OrderElement encoding")
			}
		}
	*/
	var in [sm2p256ElementLen]byte
	copy(in[:], v)
	sm2p256InvertEndianness(in[:])
	var tmp sm2p256NonMontgomeryDomainFieldElement
	sm2p256FromBytes((*sm2p256UntypedFieldElement)(&tmp), &in)
	sm2p256OrderToMontgomery(&e.x, &tmp)
	return e, nil
}

// Bytes returns the 32-byte big-endian encoding of e.
func (e *SM2P256OrderElement) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [sm2p256ElementLen]byte
	return e.bytes(&out)
}

func (e *SM2P256OrderElement) bytes(out *[sm2p256ElementLen]byte) []byte {
	var tmp sm2p256NonMontgomeryDomainFieldElement
	sm2p256OrderFromMontgomery(&tmp, &e.x)
	sm2p256ToBytes(out, (*sm2p256UntypedFieldElement)(&tmp))
	sm2p256InvertEndianness(out[:])
	return out[:]
}

// sm2p256OrderFromMontgomery translates a field element out of the Montgomery domain.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	eval out1 mod m = (eval arg1 * ((2^64)⁻¹ mod m)^4) mod m
//	0 ≤ eval out1 < m
func sm2p256OrderFromMontgomery(out1 *sm2p256NonMontgomeryDomainFieldElement, arg1 *sm2p256MontgomeryDomainFieldElement) {
	x1 := arg1[0]
	_, y1 := bits.Mul64(arg1[0], orderK0)
	var x2 uint64
	var x3 uint64
	x3, x2 = bits.Mul64(y1, 0xfffffffeffffffff)
	var x4 uint64
	var x5 uint64
	x5, x4 = bits.Mul64(y1, 0xffffffffffffffff)
	var x6 uint64
	var x7 uint64
	x7, x6 = bits.Mul64(y1, 0x7203df6b21c6052b)
	var x8 uint64
	var x9 uint64
	x9, x8 = bits.Mul64(y1, 0x53bbf40939d54123)
	var x10 uint64
	var x11 uint64
	x10, x11 = bits.Add64(x9, x6, uint64(0x0))
	var x12 uint64
	var x13 uint64
	x12, x13 = bits.Add64(x7, x4, uint64(sm2p256Uint1(x11)))
	var x14 uint64
	var x15 uint64
	x14, x15 = bits.Add64(x5, x2, uint64(sm2p256Uint1(x13)))
	var x17 uint64
	_, x17 = bits.Add64(x1, x8, uint64(0x0))
	var x18 uint64
	var x19 uint64
	x18, x19 = bits.Add64(uint64(0x0), x10, uint64(sm2p256Uint1(x17)))
	var x20 uint64
	var x21 uint64
	x20, x21 = bits.Add64(uint64(0x0), x12, uint64(sm2p256Uint1(x19)))
	var x22 uint64
	var x23 uint64
	x22, x23 = bits.Add64(uint64(0x0), x14, uint64(sm2p256Uint1(x21)))
	var x24 uint64
	var x25 uint64
	x24, x25 = bits.Add64(x18, arg1[1], uint64(0x0))
	var x26 uint64
	var x27 uint64
	x26, x27 = bits.Add64(x20, uint64(0x0), uint64(sm2p256Uint1(x25)))
	var x28 uint64
	var x29 uint64
	x28, x29 = bits.Add64(x22, uint64(0x0), uint64(sm2p256Uint1(x27)))
	var x30 uint64
	var x31 uint64
	_, y24 := bits.Mul64(x24, orderK0)
	x31, x30 = bits.Mul64(y24, 0xfffffffeffffffff)
	var x32 uint64
	var x33 uint64
	x33, x32 = bits.Mul64(y24, 0xffffffffffffffff)
	var x34 uint64
	var x35 uint64
	x35, x34 = bits.Mul64(y24, 0x7203df6b21c6052b)
	var x36 uint64
	var x37 uint64
	x37, x36 = bits.Mul64(y24, 0x53bbf40939d54123)
	var x38 uint64
	var x39 uint64
	x38, x39 = bits.Add64(x37, x34, uint64(0x0))
	var x40 uint64
	var x41 uint64
	x40, x41 = bits.Add64(x35, x32, uint64(sm2p256Uint1(x39)))
	var x42 uint64
	var x43 uint64
	x42, x43 = bits.Add64(x33, x30, uint64(sm2p256Uint1(x41)))
	var x45 uint64
	_, x45 = bits.Add64(x24, x36, uint64(0x0))
	var x46 uint64
	var x47 uint64
	x46, x47 = bits.Add64(x26, x38, uint64(sm2p256Uint1(x45)))
	var x48 uint64
	var x49 uint64
	x48, x49 = bits.Add64(x28, x40, uint64(sm2p256Uint1(x47)))
	var x50 uint64
	var x51 uint64
	x50, x51 = bits.Add64((uint64(sm2p256Uint1(x29)) + (uint64(sm2p256Uint1(x23)) + (uint64(sm2p256Uint1(x15)) + x3))), x42, uint64(sm2p256Uint1(x49)))
	var x52 uint64
	var x53 uint64
	x52, x53 = bits.Add64(x46, arg1[2], uint64(0x0))
	var x54 uint64
	var x55 uint64
	x54, x55 = bits.Add64(x48, uint64(0x0), uint64(sm2p256Uint1(x53)))
	var x56 uint64
	var x57 uint64
	x56, x57 = bits.Add64(x50, uint64(0x0), uint64(sm2p256Uint1(x55)))
	var x58 uint64
	var x59 uint64
	_, y52 := bits.Mul64(x52, orderK0)
	x59, x58 = bits.Mul64(y52, 0xfffffffeffffffff)
	var x60 uint64
	var x61 uint64
	x61, x60 = bits.Mul64(y52, 0xffffffffffffffff)
	var x62 uint64
	var x63 uint64
	x63, x62 = bits.Mul64(y52, 0x7203df6b21c6052b)
	var x64 uint64
	var x65 uint64
	x65, x64 = bits.Mul64(y52, 0x53bbf40939d54123)
	var x66 uint64
	var x67 uint64
	x66, x67 = bits.Add64(x65, x62, uint64(0x0))
	var x68 uint64
	var x69 uint64
	x68, x69 = bits.Add64(x63, x60, uint64(sm2p256Uint1(x67)))
	var x70 uint64
	var x71 uint64
	x70, x71 = bits.Add64(x61, x58, uint64(sm2p256Uint1(x69)))
	var x73 uint64
	_, x73 = bits.Add64(x52, x64, uint64(0x0))
	var x74 uint64
	var x75 uint64
	x74, x75 = bits.Add64(x54, x66, uint64(sm2p256Uint1(x73)))
	var x76 uint64
	var x77 uint64
	x76, x77 = bits.Add64(x56, x68, uint64(sm2p256Uint1(x75)))
	var x78 uint64
	var x79 uint64
	x78, x79 = bits.Add64((uint64(sm2p256Uint1(x57)) + (uint64(sm2p256Uint1(x51)) + (uint64(sm2p256Uint1(x43)) + x31))), x70, uint64(sm2p256Uint1(x77)))
	var x80 uint64
	var x81 uint64
	x80, x81 = bits.Add64(x74, arg1[3], uint64(0x0))
	var x82 uint64
	var x83 uint64
	x82, x83 = bits.Add64(x76, uint64(0x0), uint64(sm2p256Uint1(x81)))
	var x84 uint64
	var x85 uint64
	x84, x85 = bits.Add64(x78, uint64(0x0), uint64(sm2p256Uint1(x83)))
	var x86 uint64
	var x87 uint64
	_, y80 := bits.Mul64(x80, orderK0)
	x87, x86 = bits.Mul64(y80, 0xfffffffeffffffff)
	var x88 uint64
	var x89 uint64
	x89, x88 = bits.Mul64(y80, 0xffffffffffffffff)
	var x90 uint64
	var x91 uint64
	x91, x90 = bits.Mul64(y80, 0x7203df6b21c6052b)
	var x92 uint64
	var x93 uint64
	x93, x92 = bits.Mul64(y80, 0x53bbf40939d54123)
	var x94 uint64
	var x95 uint64
	x94, x95 = bits.Add64(x93, x90, uint64(0x0))
	var x96 uint64
	var x97 uint64
	x96, x97 = bits.Add64(x91, x88, uint64(sm2p256Uint1(x95)))
	var x98 uint64
	var x99 uint64
	x98, x99 = bits.Add64(x89, x86, uint64(sm2p256Uint1(x97)))
	var x101 uint64
	_, x101 = bits.Add64(x80, x92, uint64(0x0))
	var x102 uint64
	var x103 uint64
	x102, x103 = bits.Add64(x82, x94, uint64(sm2p256Uint1(x101)))
	var x104 uint64
	var x105 uint64
	x104, x105 = bits.Add64(x84, x96, uint64(sm2p256Uint1(x103)))
	var x106 uint64
	var x107 uint64
	x106, x107 = bits.Add64((uint64(sm2p256Uint1(x85)) + (uint64(sm2p256Uint1(x79)) + (uint64(sm2p256Uint1(x71)) + x59))), x98, uint64(sm2p256Uint1(x105)))
	x108 := (uint64(sm2p256Uint1(x107)) + (uint64(sm2p256Uint1(x99)) + x87))
	var x109 uint64
	var x110 uint64
	x109, x110 = bits.Sub64(x102, 0x53bbf40939d54123, uint64(0x0))
	var x111 uint64
	var x112 uint64
	x111, x112 = bits.Sub64(x104, 0x7203df6b21c6052b, uint64(sm2p256Uint1(x110)))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Sub64(x106, 0xffffffffffffffff, uint64(sm2p256Uint1(x112)))
	var x115 uint64
	var x116 uint64
	x115, x116 = bits.Sub64(x108, 0xfffffffeffffffff, uint64(sm2p256Uint1(x114)))
	var x118 uint64
	_, x118 = bits.Sub64(uint64(0x0), uint64(0x0), uint64(sm2p256Uint1(x116)))
	var x119 uint64
	sm2p256CmovznzU64(&x119, sm2p256Uint1(x118), x109, x102)
	var x120 uint64
	sm2p256CmovznzU64(&x120, sm2p256Uint1(x118), x111, x104)
	var x121 uint64
	sm2p256CmovznzU64(&x121, sm2p256Uint1(x118), x113, x106)
	var x122 uint64
	sm2p256CmovznzU64(&x122, sm2p256Uint1(x118), x115, x108)
	out1[0] = x119
	out1[1] = x120
	out1[2] = x121
	out1[3] = x122
}

// sm2p256OrderToMontgomery translates a field element into the Montgomery domain.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	eval (from_montgomery out1) mod m = eval arg1 mod m
//	0 ≤ eval out1 < m
func sm2p256OrderToMontgomery(out1 *sm2p256MontgomeryDomainFieldElement, arg1 *sm2p256NonMontgomeryDomainFieldElement) {
	x1 := arg1[1]
	x2 := arg1[2]
	x3 := arg1[3]
	x4 := arg1[0]
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x4, 0x1eb5e412a22b3d3b)
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x4, 0x620fc84c3affe0d4)
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x4, 0x3464504ade6fa2fa)
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x4, 0x901192af7c114f20)
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Add64(x12, x9, uint64(0x0))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Add64(x10, x7, uint64(sm2p256Uint1(x14)))
	var x17 uint64
	var x18 uint64
	x17, x18 = bits.Add64(x8, x5, uint64(sm2p256Uint1(x16)))
	var x19 uint64
	var x20 uint64
	_, y11 := bits.Mul64(x11, orderK0)
	x20, x19 = bits.Mul64(y11, 0xfffffffeffffffff)
	var x21 uint64
	var x22 uint64
	x22, x21 = bits.Mul64(y11, 0xffffffffffffffff)
	var x23 uint64
	var x24 uint64
	x24, x23 = bits.Mul64(y11, 0x7203df6b21c6052b)
	var x25 uint64
	var x26 uint64
	x26, x25 = bits.Mul64(y11, 0x53bbf40939d54123)
	var x27 uint64
	var x28 uint64
	x27, x28 = bits.Add64(x26, x23, uint64(0x0))
	var x29 uint64
	var x30 uint64
	x29, x30 = bits.Add64(x24, x21, uint64(sm2p256Uint1(x28)))
	var x31 uint64
	var x32 uint64
	x31, x32 = bits.Add64(x22, x19, uint64(sm2p256Uint1(x30)))
	var x34 uint64
	_, x34 = bits.Add64(x11, x25, uint64(0x0))
	var x35 uint64
	var x36 uint64
	x35, x36 = bits.Add64(x13, x27, uint64(sm2p256Uint1(x34)))
	var x37 uint64
	var x38 uint64
	x37, x38 = bits.Add64(x15, x29, uint64(sm2p256Uint1(x36)))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x17, x31, uint64(sm2p256Uint1(x38)))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64((uint64(sm2p256Uint1(x18)) + x6), (uint64(sm2p256Uint1(x32)) + x20), uint64(sm2p256Uint1(x40)))
	var x43 uint64
	var x44 uint64
	x44, x43 = bits.Mul64(x1, 0x1eb5e412a22b3d3b)
	var x45 uint64
	var x46 uint64
	x46, x45 = bits.Mul64(x1, 0x620fc84c3affe0d4)
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(x1, 0x3464504ade6fa2fa)
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(x1, 0x901192af7c114f20)
	var x51 uint64
	var x52 uint64
	x51, x52 = bits.Add64(x50, x47, uint64(0x0))
	var x53 uint64
	var x54 uint64
	x53, x54 = bits.Add64(x48, x45, uint64(sm2p256Uint1(x52)))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x46, x43, uint64(sm2p256Uint1(x54)))
	var x57 uint64
	var x58 uint64
	x57, x58 = bits.Add64(x35, x49, uint64(0x0))
	var x59 uint64
	var x60 uint64
	x59, x60 = bits.Add64(x37, x51, uint64(sm2p256Uint1(x58)))
	var x61 uint64
	var x62 uint64
	x61, x62 = bits.Add64(x39, x53, uint64(sm2p256Uint1(x60)))
	var x63 uint64
	var x64 uint64
	x63, x64 = bits.Add64(x41, x55, uint64(sm2p256Uint1(x62)))
	var x65 uint64
	var x66 uint64
	_, y57 := bits.Mul64(x57, orderK0)
	x66, x65 = bits.Mul64(y57, 0xfffffffeffffffff)
	var x67 uint64
	var x68 uint64
	x68, x67 = bits.Mul64(y57, 0xffffffffffffffff)
	var x69 uint64
	var x70 uint64
	x70, x69 = bits.Mul64(y57, 0x7203df6b21c6052b)
	var x71 uint64
	var x72 uint64
	x72, x71 = bits.Mul64(y57, 0x53bbf40939d54123)
	var x73 uint64
	var x74 uint64
	x73, x74 = bits.Add64(x72, x69, uint64(0x0))
	var x75 uint64
	var x76 uint64
	x75, x76 = bits.Add64(x70, x67, uint64(sm2p256Uint1(x74)))
	var x77 uint64
	var x78 uint64
	x77, x78 = bits.Add64(x68, x65, uint64(sm2p256Uint1(x76)))
	var x80 uint64
	_, x80 = bits.Add64(x57, x71, uint64(0x0))
	var x81 uint64
	var x82 uint64
	x81, x82 = bits.Add64(x59, x73, uint64(sm2p256Uint1(x80)))
	var x83 uint64
	var x84 uint64
	x83, x84 = bits.Add64(x61, x75, uint64(sm2p256Uint1(x82)))
	var x85 uint64
	var x86 uint64
	x85, x86 = bits.Add64(x63, x77, uint64(sm2p256Uint1(x84)))
	var x87 uint64
	var x88 uint64
	x87, x88 = bits.Add64(((uint64(sm2p256Uint1(x64)) + uint64(sm2p256Uint1(x42))) + (uint64(sm2p256Uint1(x56)) + x44)), (uint64(sm2p256Uint1(x78)) + x66), uint64(sm2p256Uint1(x86)))
	var x89 uint64
	var x90 uint64
	x90, x89 = bits.Mul64(x2, 0x1eb5e412a22b3d3b)
	var x91 uint64
	var x92 uint64
	x92, x91 = bits.Mul64(x2, 0x620fc84c3affe0d4)
	var x93 uint64
	var x94 uint64
	x94, x93 = bits.Mul64(x2, 0x3464504ade6fa2fa)
	var x95 uint64
	var x96 uint64
	x96, x95 = bits.Mul64(x2, 0x901192af7c114f20)
	var x97 uint64
	var x98 uint64
	x97, x98 = bits.Add64(x96, x93, uint64(0x0))
	var x99 uint64
	var x100 uint64
	x99, x100 = bits.Add64(x94, x91, uint64(sm2p256Uint1(x98)))
	var x101 uint64
	var x102 uint64
	x101, x102 = bits.Add64(x92, x89, uint64(sm2p256Uint1(x100)))
	var x103 uint64
	var x104 uint64
	x103, x104 = bits.Add64(x81, x95, uint64(0x0))
	var x105 uint64
	var x106 uint64
	x105, x106 = bits.Add64(x83, x97, uint64(sm2p256Uint1(x104)))
	var x107 uint64
	var x108 uint64
	x107, x108 = bits.Add64(x85, x99, uint64(sm2p256Uint1(x106)))
	var x109 uint64
	var x110 uint64
	x109, x110 = bits.Add64(x87, x101, uint64(sm2p256Uint1(x108)))
	var x111 uint64
	var x112 uint64
	_, y103 := bits.Mul64(x103, orderK0)
	x112, x111 = bits.Mul64(y103, 0xfffffffeffffffff)
	var x113 uint64
	var x114 uint64
	x114, x113 = bits.Mul64(y103, 0xffffffffffffffff)
	var x115 uint64
	var x116 uint64
	x116, x115 = bits.Mul64(y103, 0x7203df6b21c6052b)
	var x117 uint64
	var x118 uint64
	x118, x117 = bits.Mul64(y103, 0x53bbf40939d54123)
	var x119 uint64
	var x120 uint64
	x119, x120 = bits.Add64(x118, x115, uint64(0x0))
	var x121 uint64
	var x122 uint64
	x121, x122 = bits.Add64(x116, x113, uint64(sm2p256Uint1(x120)))
	var x123 uint64
	var x124 uint64
	x123, x124 = bits.Add64(x114, x111, uint64(sm2p256Uint1(x122)))
	var x126 uint64
	_, x126 = bits.Add64(x103, x117, uint64(0x0))
	var x127 uint64
	var x128 uint64
	x127, x128 = bits.Add64(x105, x119, uint64(sm2p256Uint1(x126)))
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x107, x121, uint64(sm2p256Uint1(x128)))
	var x131 uint64
	var x132 uint64
	x131, x132 = bits.Add64(x109, x123, uint64(sm2p256Uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(((uint64(sm2p256Uint1(x110)) + uint64(sm2p256Uint1(x88))) + (uint64(sm2p256Uint1(x102)) + x90)), (uint64(sm2p256Uint1(x124)) + x112), uint64(sm2p256Uint1(x132)))
	var x135 uint64
	var x136 uint64
	x136, x135 = bits.Mul64(x3, 0x1eb5e412a22b3d3b)
	var x137 uint64
	var x138 uint64
	x138, x137 = bits.Mul64(x3, 0x620fc84c3affe0d4)
	var x139 uint64
	var x140 uint64
	x140, x139 = bits.Mul64(x3, 0x3464504ade6fa2fa)
	var x141 uint64
	var x142 uint64
	x142, x141 = bits.Mul64(x3, 0x901192af7c114f20)
	var x143 uint64
	var x144 uint64
	x143, x144 = bits.Add64(x142, x139, uint64(0x0))
	var x145 uint64
	var x146 uint64
	x145, x146 = bits.Add64(x140, x137, uint64(sm2p256Uint1(x144)))
	var x147 uint64
	var x148 uint64
	x147, x148 = bits.Add64(x138, x135, uint64(sm2p256Uint1(x146)))
	var x149 uint64
	var x150 uint64
	x149, x150 = bits.Add64(x127, x141, uint64(0x0))
	var x151 uint64
	var x152 uint64
	x151, x152 = bits.Add64(x129, x143, uint64(sm2p256Uint1(x150)))
	var x153 uint64
	var x154 uint64
	x153, x154 = bits.Add64(x131, x145, uint64(sm2p256Uint1(x152)))
	var x155 uint64
	var x156 uint64
	x155, x156 = bits.Add64(x133, x147, uint64(sm2p256Uint1(x154)))
	var x157 uint64
	var x158 uint64
	_, y149 := bits.Mul64(x149, orderK0)
	x158, x157 = bits.Mul64(y149, 0xfffffffeffffffff)
	var x159 uint64
	var x160 uint64
	x160, x159 = bits.Mul64(y149, 0xffffffffffffffff)
	var x161 uint64
	var x162 uint64
	x162, x161 = bits.Mul64(y149, 0x7203df6b21c6052b)
	var x163 uint64
	var x164 uint64
	x164, x163 = bits.Mul64(y149, 0x53bbf40939d54123)
	var x165 uint64
	var x166 uint64
	x165, x166 = bits.Add64(x164, x161, uint64(0x0))
	var x167 uint64
	var x168 uint64
	x167, x168 = bits.Add64(x162, x159, uint64(sm2p256Uint1(x166)))
	var x169 uint64
	var x170 uint64
	x169, x170 = bits.Add64(x160, x157, uint64(sm2p256Uint1(x168)))
	var x172 uint64
	_, x172 = bits.Add64(x149, x163, uint64(0x0))
	var x173 uint64
	var x174 uint64
	x173, x174 = bits.Add64(x151, x165, uint64(sm2p256Uint1(x172)))
	var x175 uint64
	var x176 uint64
	x175, x176 = bits.Add64(x153, x167, uint64(sm2p256Uint1(x174)))
	var x177 uint64
	var x178 uint64
	x177, x178 = bits.Add64(x155, x169, uint64(sm2p256Uint1(x176)))
	var x179 uint64
	var x180 uint64
	x179, x180 = bits.Add64(((uint64(sm2p256Uint1(x156)) + uint64(sm2p256Uint1(x134))) + (uint64(sm2p256Uint1(x148)) + x136)), (uint64(sm2p256Uint1(x170)) + x158), uint64(sm2p256Uint1(x178)))
	var x181 uint64
	var x182 uint64
	x181, x182 = bits.Sub64(x173, 0x53bbf40939d54123, uint64(0x0))
	var x183 uint64
	var x184 uint64
	x183, x184 = bits.Sub64(x175, 0x7203df6b21c6052b, uint64(sm2p256Uint1(x182)))
	var x185 uint64
	var x186 uint64
	x185, x186 = bits.Sub64(x177, 0xffffffffffffffff, uint64(sm2p256Uint1(x184)))
	var x187 uint64
	var x188 uint64
	x187, x188 = bits.Sub64(x179, 0xfffffffeffffffff, uint64(sm2p256Uint1(x186)))
	var x190 uint64
	_, x190 = bits.Sub64(uint64(sm2p256Uint1(x180)), uint64(0x0), uint64(sm2p256Uint1(x188)))
	var x191 uint64
	sm2p256CmovznzU64(&x191, sm2p256Uint1(x190), x181, x173)
	var x192 uint64
	sm2p256CmovznzU64(&x192, sm2p256Uint1(x190), x183, x175)
	var x193 uint64
	sm2p256CmovznzU64(&x193, sm2p256Uint1(x190), x185, x177)
	var x194 uint64
	sm2p256CmovznzU64(&x194, sm2p256Uint1(x190), x187, x179)
	out1[0] = x191
	out1[1] = x192
	out1[2] = x193
	out1[3] = x194
}

// Invert sets e = 1/x, and returns e.
//
// If x == 0, Invert returns e = 0.
func (e *SM2P256Element) Invert(x *SM2P256Element) *SM2P256Element {
	// Inversion is implemented as exponentiation with exponent p − 2.
	// The sequence of 14 multiplications and 255 squarings is derived from the
	// following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
	//
	//	_10      = 2*1
	//	_11      = 1 + _10
	//	_110     = 2*_11
	//	_111     = 1 + _110
	//	_111000  = _111 << 3
	//	_111111  = _111 + _111000
	//	_1111110 = 2*_111111
	//	_1111111 = 1 + _1111110
	//	x12      = _1111110 << 5 + _111111
	//	x24      = x12 << 12 + x12
	//	x31      = x24 << 7 + _1111111
	//	i39      = x31 << 2
	//	i68      = i39 << 29
	//	x62      = x31 + i68
	//	i71      = i68 << 2
	//	x64      = i39 + i71 + _11
	//	i265     = ((i71 << 32 + x64) << 64 + x64) << 94
	//	return     (x62 + i265) << 2 + 1
	//
	var z = new(SM2P256Element).Set(e)
	var t0 = new(SM2P256Element)
	var t1 = new(SM2P256Element)
	var t2 = new(SM2P256Element)

	z.Square(x)
	t0.Mul(x, z)
	z.Square(t0)
	z.Mul(x, z)
	t1.Square(z)
	for s := 1; s < 3; s++ {
		t1.Square(t1)
	}
	t1.Mul(z, t1)
	t2.Square(t1)
	z.Mul(x, t2)
	for s := 0; s < 5; s++ {
		t2.Square(t2)
	}
	t1.Mul(t1, t2)
	t2.Square(t1)
	for s := 1; s < 12; s++ {
		t2.Square(t2)
	}
	t1.Mul(t1, t2)
	for s := 0; s < 7; s++ {
		t1.Square(t1)
	}
	z.Mul(z, t1)
	t2.Square(z)
	for s := 1; s < 2; s++ {
		t2.Square(t2)
	}
	t1.Square(t2)
	for s := 1; s < 29; s++ {
		t1.Square(t1)
	}
	z.Mul(z, t1)
	for s := 0; s < 2; s++ {
		t1.Square(t1)
	}
	t2.Mul(t2, t1)
	t0.Mul(t0, t2)
	for s := 0; s < 32; s++ {
		t1.Square(t1)
	}
	t1.Mul(t0, t1)
	for s := 0; s < 64; s++ {
		t1.Square(t1)
	}
	t0.Mul(t0, t1)
	for s := 0; s < 94; s++ {
		t0.Square(t0)
	}
	z.Mul(z, t0)
	for s := 0; s < 2; s++ {
		z.Square(z)
	}
	z.Mul(x, z)
	return e.Set(z)
}

// Code generated by Fiat Cryptography. DO NOT EDIT.
//
// Autogenerated: word_by_word_montgomery --lang Go --no-wide-int --cmovznz-by-mul --relax-primitive-carry-to-bitwidth 32,64 --internal-static --public-function-case camelCase --public-type-case camelCase --private-function-case camelCase --private-type-case camelCase --doc-text-before-function-name '' --doc-newline-before-package-declaration --doc-prepend-header 'Code generated by Fiat Cryptography. DO NOT EDIT.' --package-name fiat --no-prefix-fiat sm2p256 64 '2^256 - 2^224 - 2^96 + 2^64 - 1' mul square add sub one from_montgomery to_montgomery selectznz to_bytes from_bytes
//
// curve description: sm2p256
//
// machine_wordsize = 64 (from "64")
//
// requested operations: mul, square, add, sub, one, from_montgomery, to_montgomery, selectznz, to_bytes, from_bytes
//
// m = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff (from "2^256 - 2^224 - 2^96 + 2^64 - 1")
//
//
//
// NOTE: In addition to the bounds specified above each function, all
//
//   functions synthesized for this Montgomery arithmetic require the
//
//   input to be strictly less than the prime modulus (m), and also
//
//   require the input to be in the unique saturated representation.
//
//   All functions also ensure that these two properties are true of
//
//   return values.
//
//
//
// Computed values:
//
//   eval z = z[0] + (z[1] << 64) + (z[2] << 128) + (z[3] << 192)
//
//   bytes_eval z = z[0] + (z[1] << 8) + (z[2] << 16) + (z[3] << 24) + (z[4] << 32) + (z[5] << 40) + (z[6] << 48) + (z[7] << 56) + (z[8] << 64) + (z[9] << 72) + (z[10] << 80) + (z[11] << 88) + (z[12] << 96) + (z[13] << 104) + (z[14] << 112) + (z[15] << 120) + (z[16] << 128) + (z[17] << 136) + (z[18] << 144) + (z[19] << 152) + (z[20] << 160) + (z[21] << 168) + (z[22] << 176) + (z[23] << 184) + (z[24] << 192) + (z[25] << 200) + (z[26] << 208) + (z[27] << 216) + (z[28] << 224) + (z[29] << 232) + (z[30] << 240) + (z[31] << 248)
//
//   twos_complement_eval z = let x1 := z[0] + (z[1] << 64) + (z[2] << 128) + (z[3] << 192) in
//
//                            if x1 & (2^256-1) < 2^255 then x1 & (2^256-1) else (x1 & (2^256-1)) - 2^256

type sm2p256Uint1 uint64 // We use uint64 instead of a more narrow type for performance reasons; see https://github.com/mit-plv/fiat-crypto/pull/1006#issuecomment-892625927
type sm2p256Int1 int64   // We use uint64 instead of a more narrow type for performance reasons; see https://github.com/mit-plv/fiat-crypto/pull/1006#issuecomment-892625927

// The type sm2p256MontgomeryDomainFieldElement is a field element in the Montgomery domain.
//
// Bounds: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
type sm2p256MontgomeryDomainFieldElement [4]uint64

// The type sm2p256NonMontgomeryDomainFieldElement is a field element NOT in the Montgomery domain.
//
// Bounds: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
type sm2p256NonMontgomeryDomainFieldElement [4]uint64

// sm2p256CmovznzU64 is a single-word conditional move.
//
// Postconditions:
//
//	out1 = (if arg1 = 0 then arg2 else arg3)
//
// Input Bounds:
//
//	arg1: [0x0 ~> 0x1]
//	arg2: [0x0 ~> 0xffffffffffffffff]
//	arg3: [0x0 ~> 0xffffffffffffffff]
//
// Output Bounds:
//
//	out1: [0x0 ~> 0xffffffffffffffff]
func sm2p256CmovznzU64(out1 *uint64, arg1 sm2p256Uint1, arg2 uint64, arg3 uint64) {
	x1 := (uint64(arg1) * 0xffffffffffffffff)
	x2 := ((x1 & arg3) | ((^x1) & arg2))
	*out1 = x2
}

// sm2p256Mul multiplies two field elements in the Montgomery domain.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//	0 ≤ eval arg2 < m
//
// Postconditions:
//
//	eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg2)) mod m
//	0 ≤ eval out1 < m
func sm2p256Mul(out1 *sm2p256MontgomeryDomainFieldElement, arg1 *sm2p256MontgomeryDomainFieldElement, arg2 *sm2p256MontgomeryDomainFieldElement) {
	x1 := arg1[1]
	x2 := arg1[2]
	x3 := arg1[3]
	x4 := arg1[0]
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x4, arg2[3])
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x4, arg2[2])
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x4, arg2[1])
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x4, arg2[0])
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Add64(x12, x9, uint64(0x0))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Add64(x10, x7, uint64(sm2p256Uint1(x14)))
	var x17 uint64
	var x18 uint64
	x17, x18 = bits.Add64(x8, x5, uint64(sm2p256Uint1(x16)))
	x19 := (uint64(sm2p256Uint1(x18)) + x6)
	var x20 uint64
	var x21 uint64
	x21, x20 = bits.Mul64(x11, 0xfffffffeffffffff)
	var x22 uint64
	var x23 uint64
	x23, x22 = bits.Mul64(x11, 0xffffffffffffffff)
	var x24 uint64
	var x25 uint64
	x25, x24 = bits.Mul64(x11, 0xffffffff00000000)
	var x26 uint64
	var x27 uint64
	x27, x26 = bits.Mul64(x11, 0xffffffffffffffff)
	var x28 uint64
	var x29 uint64
	x28, x29 = bits.Add64(x27, x24, uint64(0x0))
	var x30 uint64
	var x31 uint64
	x30, x31 = bits.Add64(x25, x22, uint64(sm2p256Uint1(x29)))
	var x32 uint64
	var x33 uint64
	x32, x33 = bits.Add64(x23, x20, uint64(sm2p256Uint1(x31)))
	x34 := (uint64(sm2p256Uint1(x33)) + x21)
	var x36 uint64
	_, x36 = bits.Add64(x11, x26, uint64(0x0))
	var x37 uint64
	var x38 uint64
	x37, x38 = bits.Add64(x13, x28, uint64(sm2p256Uint1(x36)))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x15, x30, uint64(sm2p256Uint1(x38)))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64(x17, x32, uint64(sm2p256Uint1(x40)))
	var x43 uint64
	var x44 uint64
	x43, x44 = bits.Add64(x19, x34, uint64(sm2p256Uint1(x42)))
	var x45 uint64
	var x46 uint64
	x46, x45 = bits.Mul64(x1, arg2[3])
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(x1, arg2[2])
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(x1, arg2[1])
	var x51 uint64
	var x52 uint64
	x52, x51 = bits.Mul64(x1, arg2[0])
	var x53 uint64
	var x54 uint64
	x53, x54 = bits.Add64(x52, x49, uint64(0x0))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x50, x47, uint64(sm2p256Uint1(x54)))
	var x57 uint64
	var x58 uint64
	x57, x58 = bits.Add64(x48, x45, uint64(sm2p256Uint1(x56)))
	x59 := (uint64(sm2p256Uint1(x58)) + x46)
	var x60 uint64
	var x61 uint64
	x60, x61 = bits.Add64(x37, x51, uint64(0x0))
	var x62 uint64
	var x63 uint64
	x62, x63 = bits.Add64(x39, x53, uint64(sm2p256Uint1(x61)))
	var x64 uint64
	var x65 uint64
	x64, x65 = bits.Add64(x41, x55, uint64(sm2p256Uint1(x63)))
	var x66 uint64
	var x67 uint64
	x66, x67 = bits.Add64(x43, x57, uint64(sm2p256Uint1(x65)))
	var x68 uint64
	var x69 uint64
	x68, x69 = bits.Add64(uint64(sm2p256Uint1(x44)), x59, uint64(sm2p256Uint1(x67)))
	var x70 uint64
	var x71 uint64
	x71, x70 = bits.Mul64(x60, 0xfffffffeffffffff)
	var x72 uint64
	var x73 uint64
	x73, x72 = bits.Mul64(x60, 0xffffffffffffffff)
	var x74 uint64
	var x75 uint64
	x75, x74 = bits.Mul64(x60, 0xffffffff00000000)
	var x76 uint64
	var x77 uint64
	x77, x76 = bits.Mul64(x60, 0xffffffffffffffff)
	var x78 uint64
	var x79 uint64
	x78, x79 = bits.Add64(x77, x74, uint64(0x0))
	var x80 uint64
	var x81 uint64
	x80, x81 = bits.Add64(x75, x72, uint64(sm2p256Uint1(x79)))
	var x82 uint64
	var x83 uint64
	x82, x83 = bits.Add64(x73, x70, uint64(sm2p256Uint1(x81)))
	x84 := (uint64(sm2p256Uint1(x83)) + x71)
	var x86 uint64
	_, x86 = bits.Add64(x60, x76, uint64(0x0))
	var x87 uint64
	var x88 uint64
	x87, x88 = bits.Add64(x62, x78, uint64(sm2p256Uint1(x86)))
	var x89 uint64
	var x90 uint64
	x89, x90 = bits.Add64(x64, x80, uint64(sm2p256Uint1(x88)))
	var x91 uint64
	var x92 uint64
	x91, x92 = bits.Add64(x66, x82, uint64(sm2p256Uint1(x90)))
	var x93 uint64
	var x94 uint64
	x93, x94 = bits.Add64(x68, x84, uint64(sm2p256Uint1(x92)))
	x95 := (uint64(sm2p256Uint1(x94)) + uint64(sm2p256Uint1(x69)))
	var x96 uint64
	var x97 uint64
	x97, x96 = bits.Mul64(x2, arg2[3])
	var x98 uint64
	var x99 uint64
	x99, x98 = bits.Mul64(x2, arg2[2])
	var x100 uint64
	var x101 uint64
	x101, x100 = bits.Mul64(x2, arg2[1])
	var x102 uint64
	var x103 uint64
	x103, x102 = bits.Mul64(x2, arg2[0])
	var x104 uint64
	var x105 uint64
	x104, x105 = bits.Add64(x103, x100, uint64(0x0))
	var x106 uint64
	var x107 uint64
	x106, x107 = bits.Add64(x101, x98, uint64(sm2p256Uint1(x105)))
	var x108 uint64
	var x109 uint64
	x108, x109 = bits.Add64(x99, x96, uint64(sm2p256Uint1(x107)))
	x110 := (uint64(sm2p256Uint1(x109)) + x97)
	var x111 uint64
	var x112 uint64
	x111, x112 = bits.Add64(x87, x102, uint64(0x0))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Add64(x89, x104, uint64(sm2p256Uint1(x112)))
	var x115 uint64
	var x116 uint64
	x115, x116 = bits.Add64(x91, x106, uint64(sm2p256Uint1(x114)))
	var x117 uint64
	var x118 uint64
	x117, x118 = bits.Add64(x93, x108, uint64(sm2p256Uint1(x116)))
	var x119 uint64
	var x120 uint64
	x119, x120 = bits.Add64(x95, x110, uint64(sm2p256Uint1(x118)))
	var x121 uint64
	var x122 uint64
	x122, x121 = bits.Mul64(x111, 0xfffffffeffffffff)
	var x123 uint64
	var x124 uint64
	x124, x123 = bits.Mul64(x111, 0xffffffffffffffff)
	var x125 uint64
	var x126 uint64
	x126, x125 = bits.Mul64(x111, 0xffffffff00000000)
	var x127 uint64
	var x128 uint64
	x128, x127 = bits.Mul64(x111, 0xffffffffffffffff)
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x128, x125, uint64(0x0))
	var x131 uint64
	var x132 uint64
	x131, x132 = bits.Add64(x126, x123, uint64(sm2p256Uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(x124, x121, uint64(sm2p256Uint1(x132)))
	x135 := (uint64(sm2p256Uint1(x134)) + x122)
	var x137 uint64
	_, x137 = bits.Add64(x111, x127, uint64(0x0))
	var x138 uint64
	var x139 uint64
	x138, x139 = bits.Add64(x113, x129, uint64(sm2p256Uint1(x137)))
	var x140 uint64
	var x141 uint64
	x140, x141 = bits.Add64(x115, x131, uint64(sm2p256Uint1(x139)))
	var x142 uint64
	var x143 uint64
	x142, x143 = bits.Add64(x117, x133, uint64(sm2p256Uint1(x141)))
	var x144 uint64
	var x145 uint64
	x144, x145 = bits.Add64(x119, x135, uint64(sm2p256Uint1(x143)))
	x146 := (uint64(sm2p256Uint1(x145)) + uint64(sm2p256Uint1(x120)))
	var x147 uint64
	var x148 uint64
	x148, x147 = bits.Mul64(x3, arg2[3])
	var x149 uint64
	var x150 uint64
	x150, x149 = bits.Mul64(x3, arg2[2])
	var x151 uint64
	var x152 uint64
	x152, x151 = bits.Mul64(x3, arg2[1])
	var x153 uint64
	var x154 uint64
	x154, x153 = bits.Mul64(x3, arg2[0])
	var x155 uint64
	var x156 uint64
	x155, x156 = bits.Add64(x154, x151, uint64(0x0))
	var x157 uint64
	var x158 uint64
	x157, x158 = bits.Add64(x152, x149, uint64(sm2p256Uint1(x156)))
	var x159 uint64
	var x160 uint64
	x159, x160 = bits.Add64(x150, x147, uint64(sm2p256Uint1(x158)))
	x161 := (uint64(sm2p256Uint1(x160)) + x148)
	var x162 uint64
	var x163 uint64
	x162, x163 = bits.Add64(x138, x153, uint64(0x0))
	var x164 uint64
	var x165 uint64
	x164, x165 = bits.Add64(x140, x155, uint64(sm2p256Uint1(x163)))
	var x166 uint64
	var x167 uint64
	x166, x167 = bits.Add64(x142, x157, uint64(sm2p256Uint1(x165)))
	var x168 uint64
	var x169 uint64
	x168, x169 = bits.Add64(x144, x159, uint64(sm2p256Uint1(x167)))
	var x170 uint64
	var x171 uint64
	x170, x171 = bits.Add64(x146, x161, uint64(sm2p256Uint1(x169)))
	var x172 uint64
	var x173 uint64
	x173, x172 = bits.Mul64(x162, 0xfffffffeffffffff)
	var x174 uint64
	var x175 uint64
	x175, x174 = bits.Mul64(x162, 0xffffffffffffffff)
	var x176 uint64
	var x177 uint64
	x177, x176 = bits.Mul64(x162, 0xffffffff00000000)
	var x178 uint64
	var x179 uint64
	x179, x178 = bits.Mul64(x162, 0xffffffffffffffff)
	var x180 uint64
	var x181 uint64
	x180, x181 = bits.Add64(x179, x176, uint64(0x0))
	var x182 uint64
	var x183 uint64
	x182, x183 = bits.Add64(x177, x174, uint64(sm2p256Uint1(x181)))
	var x184 uint64
	var x185 uint64
	x184, x185 = bits.Add64(x175, x172, uint64(sm2p256Uint1(x183)))
	x186 := (uint64(sm2p256Uint1(x185)) + x173)
	var x188 uint64
	_, x188 = bits.Add64(x162, x178, uint64(0x0))
	var x189 uint64
	var x190 uint64
	x189, x190 = bits.Add64(x164, x180, uint64(sm2p256Uint1(x188)))
	var x191 uint64
	var x192 uint64
	x191, x192 = bits.Add64(x166, x182, uint64(sm2p256Uint1(x190)))
	var x193 uint64
	var x194 uint64
	x193, x194 = bits.Add64(x168, x184, uint64(sm2p256Uint1(x192)))
	var x195 uint64
	var x196 uint64
	x195, x196 = bits.Add64(x170, x186, uint64(sm2p256Uint1(x194)))
	x197 := (uint64(sm2p256Uint1(x196)) + uint64(sm2p256Uint1(x171)))
	var x198 uint64
	var x199 uint64
	x198, x199 = bits.Sub64(x189, 0xffffffffffffffff, uint64(0x0))
	var x200 uint64
	var x201 uint64
	x200, x201 = bits.Sub64(x191, 0xffffffff00000000, uint64(sm2p256Uint1(x199)))
	var x202 uint64
	var x203 uint64
	x202, x203 = bits.Sub64(x193, 0xffffffffffffffff, uint64(sm2p256Uint1(x201)))
	var x204 uint64
	var x205 uint64
	x204, x205 = bits.Sub64(x195, 0xfffffffeffffffff, uint64(sm2p256Uint1(x203)))
	var x207 uint64
	_, x207 = bits.Sub64(x197, uint64(0x0), uint64(sm2p256Uint1(x205)))
	var x208 uint64
	sm2p256CmovznzU64(&x208, sm2p256Uint1(x207), x198, x189)
	var x209 uint64
	sm2p256CmovznzU64(&x209, sm2p256Uint1(x207), x200, x191)
	var x210 uint64
	sm2p256CmovznzU64(&x210, sm2p256Uint1(x207), x202, x193)
	var x211 uint64
	sm2p256CmovznzU64(&x211, sm2p256Uint1(x207), x204, x195)
	out1[0] = x208
	out1[1] = x209
	out1[2] = x210
	out1[3] = x211
}

// sm2p256Square squares a field element in the Montgomery domain.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg1)) mod m
//	0 ≤ eval out1 < m
func sm2p256Square(out1 *sm2p256MontgomeryDomainFieldElement, arg1 *sm2p256MontgomeryDomainFieldElement) {
	x1 := arg1[1]
	x2 := arg1[2]
	x3 := arg1[3]
	x4 := arg1[0]
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x4, arg1[3])
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x4, arg1[2])
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x4, arg1[1])
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x4, arg1[0])
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Add64(x12, x9, uint64(0x0))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Add64(x10, x7, uint64(sm2p256Uint1(x14)))
	var x17 uint64
	var x18 uint64
	x17, x18 = bits.Add64(x8, x5, uint64(sm2p256Uint1(x16)))
	x19 := (uint64(sm2p256Uint1(x18)) + x6)
	var x20 uint64
	var x21 uint64
	x21, x20 = bits.Mul64(x11, 0xfffffffeffffffff)
	var x22 uint64
	var x23 uint64
	x23, x22 = bits.Mul64(x11, 0xffffffffffffffff)
	var x24 uint64
	var x25 uint64
	x25, x24 = bits.Mul64(x11, 0xffffffff00000000)
	var x26 uint64
	var x27 uint64
	x27, x26 = bits.Mul64(x11, 0xffffffffffffffff)
	var x28 uint64
	var x29 uint64
	x28, x29 = bits.Add64(x27, x24, uint64(0x0))
	var x30 uint64
	var x31 uint64
	x30, x31 = bits.Add64(x25, x22, uint64(sm2p256Uint1(x29)))
	var x32 uint64
	var x33 uint64
	x32, x33 = bits.Add64(x23, x20, uint64(sm2p256Uint1(x31)))
	x34 := (uint64(sm2p256Uint1(x33)) + x21)
	var x36 uint64
	_, x36 = bits.Add64(x11, x26, uint64(0x0))
	var x37 uint64
	var x38 uint64
	x37, x38 = bits.Add64(x13, x28, uint64(sm2p256Uint1(x36)))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x15, x30, uint64(sm2p256Uint1(x38)))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64(x17, x32, uint64(sm2p256Uint1(x40)))
	var x43 uint64
	var x44 uint64
	x43, x44 = bits.Add64(x19, x34, uint64(sm2p256Uint1(x42)))
	var x45 uint64
	var x46 uint64
	x46, x45 = bits.Mul64(x1, arg1[3])
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(x1, arg1[2])
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(x1, arg1[1])
	var x51 uint64
	var x52 uint64
	x52, x51 = bits.Mul64(x1, arg1[0])
	var x53 uint64
	var x54 uint64
	x53, x54 = bits.Add64(x52, x49, uint64(0x0))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x50, x47, uint64(sm2p256Uint1(x54)))
	var x57 uint64
	var x58 uint64
	x57, x58 = bits.Add64(x48, x45, uint64(sm2p256Uint1(x56)))
	x59 := (uint64(sm2p256Uint1(x58)) + x46)
	var x60 uint64
	var x61 uint64
	x60, x61 = bits.Add64(x37, x51, uint64(0x0))
	var x62 uint64
	var x63 uint64
	x62, x63 = bits.Add64(x39, x53, uint64(sm2p256Uint1(x61)))
	var x64 uint64
	var x65 uint64
	x64, x65 = bits.Add64(x41, x55, uint64(sm2p256Uint1(x63)))
	var x66 uint64
	var x67 uint64
	x66, x67 = bits.Add64(x43, x57, uint64(sm2p256Uint1(x65)))
	var x68 uint64
	var x69 uint64
	x68, x69 = bits.Add64(uint64(sm2p256Uint1(x44)), x59, uint64(sm2p256Uint1(x67)))
	var x70 uint64
	var x71 uint64
	x71, x70 = bits.Mul64(x60, 0xfffffffeffffffff)
	var x72 uint64
	var x73 uint64
	x73, x72 = bits.Mul64(x60, 0xffffffffffffffff)
	var x74 uint64
	var x75 uint64
	x75, x74 = bits.Mul64(x60, 0xffffffff00000000)
	var x76 uint64
	var x77 uint64
	x77, x76 = bits.Mul64(x60, 0xffffffffffffffff)
	var x78 uint64
	var x79 uint64
	x78, x79 = bits.Add64(x77, x74, uint64(0x0))
	var x80 uint64
	var x81 uint64
	x80, x81 = bits.Add64(x75, x72, uint64(sm2p256Uint1(x79)))
	var x82 uint64
	var x83 uint64
	x82, x83 = bits.Add64(x73, x70, uint64(sm2p256Uint1(x81)))
	x84 := (uint64(sm2p256Uint1(x83)) + x71)
	var x86 uint64
	_, x86 = bits.Add64(x60, x76, uint64(0x0))
	var x87 uint64
	var x88 uint64
	x87, x88 = bits.Add64(x62, x78, uint64(sm2p256Uint1(x86)))
	var x89 uint64
	var x90 uint64
	x89, x90 = bits.Add64(x64, x80, uint64(sm2p256Uint1(x88)))
	var x91 uint64
	var x92 uint64
	x91, x92 = bits.Add64(x66, x82, uint64(sm2p256Uint1(x90)))
	var x93 uint64
	var x94 uint64
	x93, x94 = bits.Add64(x68, x84, uint64(sm2p256Uint1(x92)))
	x95 := (uint64(sm2p256Uint1(x94)) + uint64(sm2p256Uint1(x69)))
	var x96 uint64
	var x97 uint64
	x97, x96 = bits.Mul64(x2, arg1[3])
	var x98 uint64
	var x99 uint64
	x99, x98 = bits.Mul64(x2, arg1[2])
	var x100 uint64
	var x101 uint64
	x101, x100 = bits.Mul64(x2, arg1[1])
	var x102 uint64
	var x103 uint64
	x103, x102 = bits.Mul64(x2, arg1[0])
	var x104 uint64
	var x105 uint64
	x104, x105 = bits.Add64(x103, x100, uint64(0x0))
	var x106 uint64
	var x107 uint64
	x106, x107 = bits.Add64(x101, x98, uint64(sm2p256Uint1(x105)))
	var x108 uint64
	var x109 uint64
	x108, x109 = bits.Add64(x99, x96, uint64(sm2p256Uint1(x107)))
	x110 := (uint64(sm2p256Uint1(x109)) + x97)
	var x111 uint64
	var x112 uint64
	x111, x112 = bits.Add64(x87, x102, uint64(0x0))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Add64(x89, x104, uint64(sm2p256Uint1(x112)))
	var x115 uint64
	var x116 uint64
	x115, x116 = bits.Add64(x91, x106, uint64(sm2p256Uint1(x114)))
	var x117 uint64
	var x118 uint64
	x117, x118 = bits.Add64(x93, x108, uint64(sm2p256Uint1(x116)))
	var x119 uint64
	var x120 uint64
	x119, x120 = bits.Add64(x95, x110, uint64(sm2p256Uint1(x118)))
	var x121 uint64
	var x122 uint64
	x122, x121 = bits.Mul64(x111, 0xfffffffeffffffff)
	var x123 uint64
	var x124 uint64
	x124, x123 = bits.Mul64(x111, 0xffffffffffffffff)
	var x125 uint64
	var x126 uint64
	x126, x125 = bits.Mul64(x111, 0xffffffff00000000)
	var x127 uint64
	var x128 uint64
	x128, x127 = bits.Mul64(x111, 0xffffffffffffffff)
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x128, x125, uint64(0x0))
	var x131 uint64
	var x132 uint64
	x131, x132 = bits.Add64(x126, x123, uint64(sm2p256Uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(x124, x121, uint64(sm2p256Uint1(x132)))
	x135 := (uint64(sm2p256Uint1(x134)) + x122)
	var x137 uint64
	_, x137 = bits.Add64(x111, x127, uint64(0x0))
	var x138 uint64
	var x139 uint64
	x138, x139 = bits.Add64(x113, x129, uint64(sm2p256Uint1(x137)))
	var x140 uint64
	var x141 uint64
	x140, x141 = bits.Add64(x115, x131, uint64(sm2p256Uint1(x139)))
	var x142 uint64
	var x143 uint64
	x142, x143 = bits.Add64(x117, x133, uint64(sm2p256Uint1(x141)))
	var x144 uint64
	var x145 uint64
	x144, x145 = bits.Add64(x119, x135, uint64(sm2p256Uint1(x143)))
	x146 := (uint64(sm2p256Uint1(x145)) + uint64(sm2p256Uint1(x120)))
	var x147 uint64
	var x148 uint64
	x148, x147 = bits.Mul64(x3, arg1[3])
	var x149 uint64
	var x150 uint64
	x150, x149 = bits.Mul64(x3, arg1[2])
	var x151 uint64
	var x152 uint64
	x152, x151 = bits.Mul64(x3, arg1[1])
	var x153 uint64
	var x154 uint64
	x154, x153 = bits.Mul64(x3, arg1[0])
	var x155 uint64
	var x156 uint64
	x155, x156 = bits.Add64(x154, x151, uint64(0x0))
	var x157 uint64
	var x158 uint64
	x157, x158 = bits.Add64(x152, x149, uint64(sm2p256Uint1(x156)))
	var x159 uint64
	var x160 uint64
	x159, x160 = bits.Add64(x150, x147, uint64(sm2p256Uint1(x158)))
	x161 := (uint64(sm2p256Uint1(x160)) + x148)
	var x162 uint64
	var x163 uint64
	x162, x163 = bits.Add64(x138, x153, uint64(0x0))
	var x164 uint64
	var x165 uint64
	x164, x165 = bits.Add64(x140, x155, uint64(sm2p256Uint1(x163)))
	var x166 uint64
	var x167 uint64
	x166, x167 = bits.Add64(x142, x157, uint64(sm2p256Uint1(x165)))
	var x168 uint64
	var x169 uint64
	x168, x169 = bits.Add64(x144, x159, uint64(sm2p256Uint1(x167)))
	var x170 uint64
	var x171 uint64
	x170, x171 = bits.Add64(x146, x161, uint64(sm2p256Uint1(x169)))
	var x172 uint64
	var x173 uint64
	x173, x172 = bits.Mul64(x162, 0xfffffffeffffffff)
	var x174 uint64
	var x175 uint64
	x175, x174 = bits.Mul64(x162, 0xffffffffffffffff)
	var x176 uint64
	var x177 uint64
	x177, x176 = bits.Mul64(x162, 0xffffffff00000000)
	var x178 uint64
	var x179 uint64
	x179, x178 = bits.Mul64(x162, 0xffffffffffffffff)
	var x180 uint64
	var x181 uint64
	x180, x181 = bits.Add64(x179, x176, uint64(0x0))
	var x182 uint64
	var x183 uint64
	x182, x183 = bits.Add64(x177, x174, uint64(sm2p256Uint1(x181)))
	var x184 uint64
	var x185 uint64
	x184, x185 = bits.Add64(x175, x172, uint64(sm2p256Uint1(x183)))
	x186 := (uint64(sm2p256Uint1(x185)) + x173)
	var x188 uint64
	_, x188 = bits.Add64(x162, x178, uint64(0x0))
	var x189 uint64
	var x190 uint64
	x189, x190 = bits.Add64(x164, x180, uint64(sm2p256Uint1(x188)))
	var x191 uint64
	var x192 uint64
	x191, x192 = bits.Add64(x166, x182, uint64(sm2p256Uint1(x190)))
	var x193 uint64
	var x194 uint64
	x193, x194 = bits.Add64(x168, x184, uint64(sm2p256Uint1(x192)))
	var x195 uint64
	var x196 uint64
	x195, x196 = bits.Add64(x170, x186, uint64(sm2p256Uint1(x194)))
	x197 := (uint64(sm2p256Uint1(x196)) + uint64(sm2p256Uint1(x171)))
	var x198 uint64
	var x199 uint64
	x198, x199 = bits.Sub64(x189, 0xffffffffffffffff, uint64(0x0))
	var x200 uint64
	var x201 uint64
	x200, x201 = bits.Sub64(x191, 0xffffffff00000000, uint64(sm2p256Uint1(x199)))
	var x202 uint64
	var x203 uint64
	x202, x203 = bits.Sub64(x193, 0xffffffffffffffff, uint64(sm2p256Uint1(x201)))
	var x204 uint64
	var x205 uint64
	x204, x205 = bits.Sub64(x195, 0xfffffffeffffffff, uint64(sm2p256Uint1(x203)))
	var x207 uint64
	_, x207 = bits.Sub64(x197, uint64(0x0), uint64(sm2p256Uint1(x205)))
	var x208 uint64
	sm2p256CmovznzU64(&x208, sm2p256Uint1(x207), x198, x189)
	var x209 uint64
	sm2p256CmovznzU64(&x209, sm2p256Uint1(x207), x200, x191)
	var x210 uint64
	sm2p256CmovznzU64(&x210, sm2p256Uint1(x207), x202, x193)
	var x211 uint64
	sm2p256CmovznzU64(&x211, sm2p256Uint1(x207), x204, x195)
	out1[0] = x208
	out1[1] = x209
	out1[2] = x210
	out1[3] = x211
}

// sm2p256Add adds two field elements in the Montgomery domain.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//	0 ≤ eval arg2 < m
//
// Postconditions:
//
//	eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) + eval (from_montgomery arg2)) mod m
//	0 ≤ eval out1 < m
func sm2p256Add(out1 *sm2p256MontgomeryDomainFieldElement, arg1 *sm2p256MontgomeryDomainFieldElement, arg2 *sm2p256MontgomeryDomainFieldElement) {
	var x1 uint64
	var x2 uint64
	x1, x2 = bits.Add64(arg1[0], arg2[0], uint64(0x0))
	var x3 uint64
	var x4 uint64
	x3, x4 = bits.Add64(arg1[1], arg2[1], uint64(sm2p256Uint1(x2)))
	var x5 uint64
	var x6 uint64
	x5, x6 = bits.Add64(arg1[2], arg2[2], uint64(sm2p256Uint1(x4)))
	var x7 uint64
	var x8 uint64
	x7, x8 = bits.Add64(arg1[3], arg2[3], uint64(sm2p256Uint1(x6)))
	var x9 uint64
	var x10 uint64
	x9, x10 = bits.Sub64(x1, 0xffffffffffffffff, uint64(0x0))
	var x11 uint64
	var x12 uint64
	x11, x12 = bits.Sub64(x3, 0xffffffff00000000, uint64(sm2p256Uint1(x10)))
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Sub64(x5, 0xffffffffffffffff, uint64(sm2p256Uint1(x12)))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Sub64(x7, 0xfffffffeffffffff, uint64(sm2p256Uint1(x14)))
	var x18 uint64
	_, x18 = bits.Sub64(uint64(sm2p256Uint1(x8)), uint64(0x0), uint64(sm2p256Uint1(x16)))
	var x19 uint64
	sm2p256CmovznzU64(&x19, sm2p256Uint1(x18), x9, x1)
	var x20 uint64
	sm2p256CmovznzU64(&x20, sm2p256Uint1(x18), x11, x3)
	var x21 uint64
	sm2p256CmovznzU64(&x21, sm2p256Uint1(x18), x13, x5)
	var x22 uint64
	sm2p256CmovznzU64(&x22, sm2p256Uint1(x18), x15, x7)
	out1[0] = x19
	out1[1] = x20
	out1[2] = x21
	out1[3] = x22
}

// sm2p256Sub subtracts two field elements in the Montgomery domain.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//	0 ≤ eval arg2 < m
//
// Postconditions:
//
//	eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) - eval (from_montgomery arg2)) mod m
//	0 ≤ eval out1 < m
func sm2p256Sub(out1 *sm2p256MontgomeryDomainFieldElement, arg1 *sm2p256MontgomeryDomainFieldElement, arg2 *sm2p256MontgomeryDomainFieldElement) {
	var x1 uint64
	var x2 uint64
	x1, x2 = bits.Sub64(arg1[0], arg2[0], uint64(0x0))
	var x3 uint64
	var x4 uint64
	x3, x4 = bits.Sub64(arg1[1], arg2[1], uint64(sm2p256Uint1(x2)))
	var x5 uint64
	var x6 uint64
	x5, x6 = bits.Sub64(arg1[2], arg2[2], uint64(sm2p256Uint1(x4)))
	var x7 uint64
	var x8 uint64
	x7, x8 = bits.Sub64(arg1[3], arg2[3], uint64(sm2p256Uint1(x6)))
	var x9 uint64
	sm2p256CmovznzU64(&x9, sm2p256Uint1(x8), uint64(0x0), 0xffffffffffffffff)
	var x10 uint64
	var x11 uint64
	x10, x11 = bits.Add64(x1, x9, uint64(0x0))
	var x12 uint64
	var x13 uint64
	x12, x13 = bits.Add64(x3, (x9 & 0xffffffff00000000), uint64(sm2p256Uint1(x11)))
	var x14 uint64
	var x15 uint64
	x14, x15 = bits.Add64(x5, x9, uint64(sm2p256Uint1(x13)))
	var x16 uint64
	x16, _ = bits.Add64(x7, (x9 & 0xfffffffeffffffff), uint64(sm2p256Uint1(x15)))
	out1[0] = x10
	out1[1] = x12
	out1[2] = x14
	out1[3] = x16
}

// sm2p256SetOne returns the field element one in the Montgomery domain.
//
// Postconditions:
//
//	eval (from_montgomery out1) mod m = 1 mod m
//	0 ≤ eval out1 < m
func sm2p256SetOne(out1 *sm2p256MontgomeryDomainFieldElement) {
	out1[0] = uint64(0x1)
	out1[1] = 0xffffffff
	out1[2] = uint64(0x0)
	out1[3] = 0x100000000
}

// sm2p256FromMontgomery translates a field element out of the Montgomery domain.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	eval out1 mod m = (eval arg1 * ((2^64)⁻¹ mod m)^4) mod m
//	0 ≤ eval out1 < m
func sm2p256FromMontgomery(out1 *sm2p256NonMontgomeryDomainFieldElement, arg1 *sm2p256MontgomeryDomainFieldElement) {
	x1 := arg1[0]
	var x2 uint64
	var x3 uint64
	x3, x2 = bits.Mul64(x1, 0xfffffffeffffffff)
	var x4 uint64
	var x5 uint64
	x5, x4 = bits.Mul64(x1, 0xffffffffffffffff)
	var x6 uint64
	var x7 uint64
	x7, x6 = bits.Mul64(x1, 0xffffffff00000000)
	var x8 uint64
	var x9 uint64
	x9, x8 = bits.Mul64(x1, 0xffffffffffffffff)
	var x10 uint64
	var x11 uint64
	x10, x11 = bits.Add64(x9, x6, uint64(0x0))
	var x12 uint64
	var x13 uint64
	x12, x13 = bits.Add64(x7, x4, uint64(sm2p256Uint1(x11)))
	var x14 uint64
	var x15 uint64
	x14, x15 = bits.Add64(x5, x2, uint64(sm2p256Uint1(x13)))
	var x17 uint64
	_, x17 = bits.Add64(x1, x8, uint64(0x0))
	var x18 uint64
	var x19 uint64
	x18, x19 = bits.Add64(uint64(0x0), x10, uint64(sm2p256Uint1(x17)))
	var x20 uint64
	var x21 uint64
	x20, x21 = bits.Add64(uint64(0x0), x12, uint64(sm2p256Uint1(x19)))
	var x22 uint64
	var x23 uint64
	x22, x23 = bits.Add64(uint64(0x0), x14, uint64(sm2p256Uint1(x21)))
	var x24 uint64
	var x25 uint64
	x24, x25 = bits.Add64(x18, arg1[1], uint64(0x0))
	var x26 uint64
	var x27 uint64
	x26, x27 = bits.Add64(x20, uint64(0x0), uint64(sm2p256Uint1(x25)))
	var x28 uint64
	var x29 uint64
	x28, x29 = bits.Add64(x22, uint64(0x0), uint64(sm2p256Uint1(x27)))
	var x30 uint64
	var x31 uint64
	x31, x30 = bits.Mul64(x24, 0xfffffffeffffffff)
	var x32 uint64
	var x33 uint64
	x33, x32 = bits.Mul64(x24, 0xffffffffffffffff)
	var x34 uint64
	var x35 uint64
	x35, x34 = bits.Mul64(x24, 0xffffffff00000000)
	var x36 uint64
	var x37 uint64
	x37, x36 = bits.Mul64(x24, 0xffffffffffffffff)
	var x38 uint64
	var x39 uint64
	x38, x39 = bits.Add64(x37, x34, uint64(0x0))
	var x40 uint64
	var x41 uint64
	x40, x41 = bits.Add64(x35, x32, uint64(sm2p256Uint1(x39)))
	var x42 uint64
	var x43 uint64
	x42, x43 = bits.Add64(x33, x30, uint64(sm2p256Uint1(x41)))
	var x45 uint64
	_, x45 = bits.Add64(x24, x36, uint64(0x0))
	var x46 uint64
	var x47 uint64
	x46, x47 = bits.Add64(x26, x38, uint64(sm2p256Uint1(x45)))
	var x48 uint64
	var x49 uint64
	x48, x49 = bits.Add64(x28, x40, uint64(sm2p256Uint1(x47)))
	var x50 uint64
	var x51 uint64
	x50, x51 = bits.Add64((uint64(sm2p256Uint1(x29)) + (uint64(sm2p256Uint1(x23)) + (uint64(sm2p256Uint1(x15)) + x3))), x42, uint64(sm2p256Uint1(x49)))
	var x52 uint64
	var x53 uint64
	x52, x53 = bits.Add64(x46, arg1[2], uint64(0x0))
	var x54 uint64
	var x55 uint64
	x54, x55 = bits.Add64(x48, uint64(0x0), uint64(sm2p256Uint1(x53)))
	var x56 uint64
	var x57 uint64
	x56, x57 = bits.Add64(x50, uint64(0x0), uint64(sm2p256Uint1(x55)))
	var x58 uint64
	var x59 uint64
	x59, x58 = bits.Mul64(x52, 0xfffffffeffffffff)
	var x60 uint64
	var x61 uint64
	x61, x60 = bits.Mul64(x52, 0xffffffffffffffff)
	var x62 uint64
	var x63 uint64
	x63, x62 = bits.Mul64(x52, 0xffffffff00000000)
	var x64 uint64
	var x65 uint64
	x65, x64 = bits.Mul64(x52, 0xffffffffffffffff)
	var x66 uint64
	var x67 uint64
	x66, x67 = bits.Add64(x65, x62, uint64(0x0))
	var x68 uint64
	var x69 uint64
	x68, x69 = bits.Add64(x63, x60, uint64(sm2p256Uint1(x67)))
	var x70 uint64
	var x71 uint64
	x70, x71 = bits.Add64(x61, x58, uint64(sm2p256Uint1(x69)))
	var x73 uint64
	_, x73 = bits.Add64(x52, x64, uint64(0x0))
	var x74 uint64
	var x75 uint64
	x74, x75 = bits.Add64(x54, x66, uint64(sm2p256Uint1(x73)))
	var x76 uint64
	var x77 uint64
	x76, x77 = bits.Add64(x56, x68, uint64(sm2p256Uint1(x75)))
	var x78 uint64
	var x79 uint64
	x78, x79 = bits.Add64((uint64(sm2p256Uint1(x57)) + (uint64(sm2p256Uint1(x51)) + (uint64(sm2p256Uint1(x43)) + x31))), x70, uint64(sm2p256Uint1(x77)))
	var x80 uint64
	var x81 uint64
	x80, x81 = bits.Add64(x74, arg1[3], uint64(0x0))
	var x82 uint64
	var x83 uint64
	x82, x83 = bits.Add64(x76, uint64(0x0), uint64(sm2p256Uint1(x81)))
	var x84 uint64
	var x85 uint64
	x84, x85 = bits.Add64(x78, uint64(0x0), uint64(sm2p256Uint1(x83)))
	var x86 uint64
	var x87 uint64
	x87, x86 = bits.Mul64(x80, 0xfffffffeffffffff)
	var x88 uint64
	var x89 uint64
	x89, x88 = bits.Mul64(x80, 0xffffffffffffffff)
	var x90 uint64
	var x91 uint64
	x91, x90 = bits.Mul64(x80, 0xffffffff00000000)
	var x92 uint64
	var x93 uint64
	x93, x92 = bits.Mul64(x80, 0xffffffffffffffff)
	var x94 uint64
	var x95 uint64
	x94, x95 = bits.Add64(x93, x90, uint64(0x0))
	var x96 uint64
	var x97 uint64
	x96, x97 = bits.Add64(x91, x88, uint64(sm2p256Uint1(x95)))
	var x98 uint64
	var x99 uint64
	x98, x99 = bits.Add64(x89, x86, uint64(sm2p256Uint1(x97)))
	var x101 uint64
	_, x101 = bits.Add64(x80, x92, uint64(0x0))
	var x102 uint64
	var x103 uint64
	x102, x103 = bits.Add64(x82, x94, uint64(sm2p256Uint1(x101)))
	var x104 uint64
	var x105 uint64
	x104, x105 = bits.Add64(x84, x96, uint64(sm2p256Uint1(x103)))
	var x106 uint64
	var x107 uint64
	x106, x107 = bits.Add64((uint64(sm2p256Uint1(x85)) + (uint64(sm2p256Uint1(x79)) + (uint64(sm2p256Uint1(x71)) + x59))), x98, uint64(sm2p256Uint1(x105)))
	x108 := (uint64(sm2p256Uint1(x107)) + (uint64(sm2p256Uint1(x99)) + x87))
	var x109 uint64
	var x110 uint64
	x109, x110 = bits.Sub64(x102, 0xffffffffffffffff, uint64(0x0))
	var x111 uint64
	var x112 uint64
	x111, x112 = bits.Sub64(x104, 0xffffffff00000000, uint64(sm2p256Uint1(x110)))
	var x113 uint64
	var x114 uint64
	x113, x114 = bits.Sub64(x106, 0xffffffffffffffff, uint64(sm2p256Uint1(x112)))
	var x115 uint64
	var x116 uint64
	x115, x116 = bits.Sub64(x108, 0xfffffffeffffffff, uint64(sm2p256Uint1(x114)))
	var x118 uint64
	_, x118 = bits.Sub64(uint64(0x0), uint64(0x0), uint64(sm2p256Uint1(x116)))
	var x119 uint64
	sm2p256CmovznzU64(&x119, sm2p256Uint1(x118), x109, x102)
	var x120 uint64
	sm2p256CmovznzU64(&x120, sm2p256Uint1(x118), x111, x104)
	var x121 uint64
	sm2p256CmovznzU64(&x121, sm2p256Uint1(x118), x113, x106)
	var x122 uint64
	sm2p256CmovznzU64(&x122, sm2p256Uint1(x118), x115, x108)
	out1[0] = x119
	out1[1] = x120
	out1[2] = x121
	out1[3] = x122
}

// sm2p256ToMontgomery translates a field element into the Montgomery domain.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	eval (from_montgomery out1) mod m = eval arg1 mod m
//	0 ≤ eval out1 < m
func sm2p256ToMontgomery(out1 *sm2p256MontgomeryDomainFieldElement, arg1 *sm2p256NonMontgomeryDomainFieldElement) {
	x1 := arg1[1]
	x2 := arg1[2]
	x3 := arg1[3]
	x4 := arg1[0]
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x4, 0x400000002)
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x4, 0x100000001)
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x4, 0x2ffffffff)
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x4, 0x200000003)
	var x13 uint64
	var x14 uint64
	x13, x14 = bits.Add64(x12, x9, uint64(0x0))
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Add64(x10, x7, uint64(sm2p256Uint1(x14)))
	var x17 uint64
	var x18 uint64
	x17, x18 = bits.Add64(x8, x5, uint64(sm2p256Uint1(x16)))
	var x19 uint64
	var x20 uint64
	x20, x19 = bits.Mul64(x11, 0xfffffffeffffffff)
	var x21 uint64
	var x22 uint64
	x22, x21 = bits.Mul64(x11, 0xffffffffffffffff)
	var x23 uint64
	var x24 uint64
	x24, x23 = bits.Mul64(x11, 0xffffffff00000000)
	var x25 uint64
	var x26 uint64
	x26, x25 = bits.Mul64(x11, 0xffffffffffffffff)
	var x27 uint64
	var x28 uint64
	x27, x28 = bits.Add64(x26, x23, uint64(0x0))
	var x29 uint64
	var x30 uint64
	x29, x30 = bits.Add64(x24, x21, uint64(sm2p256Uint1(x28)))
	var x31 uint64
	var x32 uint64
	x31, x32 = bits.Add64(x22, x19, uint64(sm2p256Uint1(x30)))
	var x34 uint64
	_, x34 = bits.Add64(x11, x25, uint64(0x0))
	var x35 uint64
	var x36 uint64
	x35, x36 = bits.Add64(x13, x27, uint64(sm2p256Uint1(x34)))
	var x37 uint64
	var x38 uint64
	x37, x38 = bits.Add64(x15, x29, uint64(sm2p256Uint1(x36)))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x17, x31, uint64(sm2p256Uint1(x38)))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64((uint64(sm2p256Uint1(x18)) + x6), (uint64(sm2p256Uint1(x32)) + x20), uint64(sm2p256Uint1(x40)))
	var x43 uint64
	var x44 uint64
	x44, x43 = bits.Mul64(x1, 0x400000002)
	var x45 uint64
	var x46 uint64
	x46, x45 = bits.Mul64(x1, 0x100000001)
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(x1, 0x2ffffffff)
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(x1, 0x200000003)
	var x51 uint64
	var x52 uint64
	x51, x52 = bits.Add64(x50, x47, uint64(0x0))
	var x53 uint64
	var x54 uint64
	x53, x54 = bits.Add64(x48, x45, uint64(sm2p256Uint1(x52)))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x46, x43, uint64(sm2p256Uint1(x54)))
	var x57 uint64
	var x58 uint64
	x57, x58 = bits.Add64(x35, x49, uint64(0x0))
	var x59 uint64
	var x60 uint64
	x59, x60 = bits.Add64(x37, x51, uint64(sm2p256Uint1(x58)))
	var x61 uint64
	var x62 uint64
	x61, x62 = bits.Add64(x39, x53, uint64(sm2p256Uint1(x60)))
	var x63 uint64
	var x64 uint64
	x63, x64 = bits.Add64(x41, x55, uint64(sm2p256Uint1(x62)))
	var x65 uint64
	var x66 uint64
	x66, x65 = bits.Mul64(x57, 0xfffffffeffffffff)
	var x67 uint64
	var x68 uint64
	x68, x67 = bits.Mul64(x57, 0xffffffffffffffff)
	var x69 uint64
	var x70 uint64
	x70, x69 = bits.Mul64(x57, 0xffffffff00000000)
	var x71 uint64
	var x72 uint64
	x72, x71 = bits.Mul64(x57, 0xffffffffffffffff)
	var x73 uint64
	var x74 uint64
	x73, x74 = bits.Add64(x72, x69, uint64(0x0))
	var x75 uint64
	var x76 uint64
	x75, x76 = bits.Add64(x70, x67, uint64(sm2p256Uint1(x74)))
	var x77 uint64
	var x78 uint64
	x77, x78 = bits.Add64(x68, x65, uint64(sm2p256Uint1(x76)))
	var x80 uint64
	_, x80 = bits.Add64(x57, x71, uint64(0x0))
	var x81 uint64
	var x82 uint64
	x81, x82 = bits.Add64(x59, x73, uint64(sm2p256Uint1(x80)))
	var x83 uint64
	var x84 uint64
	x83, x84 = bits.Add64(x61, x75, uint64(sm2p256Uint1(x82)))
	var x85 uint64
	var x86 uint64
	x85, x86 = bits.Add64(x63, x77, uint64(sm2p256Uint1(x84)))
	var x87 uint64
	var x88 uint64
	x87, x88 = bits.Add64(((uint64(sm2p256Uint1(x64)) + uint64(sm2p256Uint1(x42))) + (uint64(sm2p256Uint1(x56)) + x44)), (uint64(sm2p256Uint1(x78)) + x66), uint64(sm2p256Uint1(x86)))
	var x89 uint64
	var x90 uint64
	x90, x89 = bits.Mul64(x2, 0x400000002)
	var x91 uint64
	var x92 uint64
	x92, x91 = bits.Mul64(x2, 0x100000001)
	var x93 uint64
	var x94 uint64
	x94, x93 = bits.Mul64(x2, 0x2ffffffff)
	var x95 uint64
	var x96 uint64
	x96, x95 = bits.Mul64(x2, 0x200000003)
	var x97 uint64
	var x98 uint64
	x97, x98 = bits.Add64(x96, x93, uint64(0x0))
	var x99 uint64
	var x100 uint64
	x99, x100 = bits.Add64(x94, x91, uint64(sm2p256Uint1(x98)))
	var x101 uint64
	var x102 uint64
	x101, x102 = bits.Add64(x92, x89, uint64(sm2p256Uint1(x100)))
	var x103 uint64
	var x104 uint64
	x103, x104 = bits.Add64(x81, x95, uint64(0x0))
	var x105 uint64
	var x106 uint64
	x105, x106 = bits.Add64(x83, x97, uint64(sm2p256Uint1(x104)))
	var x107 uint64
	var x108 uint64
	x107, x108 = bits.Add64(x85, x99, uint64(sm2p256Uint1(x106)))
	var x109 uint64
	var x110 uint64
	x109, x110 = bits.Add64(x87, x101, uint64(sm2p256Uint1(x108)))
	var x111 uint64
	var x112 uint64
	x112, x111 = bits.Mul64(x103, 0xfffffffeffffffff)
	var x113 uint64
	var x114 uint64
	x114, x113 = bits.Mul64(x103, 0xffffffffffffffff)
	var x115 uint64
	var x116 uint64
	x116, x115 = bits.Mul64(x103, 0xffffffff00000000)
	var x117 uint64
	var x118 uint64
	x118, x117 = bits.Mul64(x103, 0xffffffffffffffff)
	var x119 uint64
	var x120 uint64
	x119, x120 = bits.Add64(x118, x115, uint64(0x0))
	var x121 uint64
	var x122 uint64
	x121, x122 = bits.Add64(x116, x113, uint64(sm2p256Uint1(x120)))
	var x123 uint64
	var x124 uint64
	x123, x124 = bits.Add64(x114, x111, uint64(sm2p256Uint1(x122)))
	var x126 uint64
	_, x126 = bits.Add64(x103, x117, uint64(0x0))
	var x127 uint64
	var x128 uint64
	x127, x128 = bits.Add64(x105, x119, uint64(sm2p256Uint1(x126)))
	var x129 uint64
	var x130 uint64
	x129, x130 = bits.Add64(x107, x121, uint64(sm2p256Uint1(x128)))
	var x131 uint64
	var x132 uint64
	x131, x132 = bits.Add64(x109, x123, uint64(sm2p256Uint1(x130)))
	var x133 uint64
	var x134 uint64
	x133, x134 = bits.Add64(((uint64(sm2p256Uint1(x110)) + uint64(sm2p256Uint1(x88))) + (uint64(sm2p256Uint1(x102)) + x90)), (uint64(sm2p256Uint1(x124)) + x112), uint64(sm2p256Uint1(x132)))
	var x135 uint64
	var x136 uint64
	x136, x135 = bits.Mul64(x3, 0x400000002)
	var x137 uint64
	var x138 uint64
	x138, x137 = bits.Mul64(x3, 0x100000001)
	var x139 uint64
	var x140 uint64
	x140, x139 = bits.Mul64(x3, 0x2ffffffff)
	var x141 uint64
	var x142 uint64
	x142, x141 = bits.Mul64(x3, 0x200000003)
	var x143 uint64
	var x144 uint64
	x143, x144 = bits.Add64(x142, x139, uint64(0x0))
	var x145 uint64
	var x146 uint64
	x145, x146 = bits.Add64(x140, x137, uint64(sm2p256Uint1(x144)))
	var x147 uint64
	var x148 uint64
	x147, x148 = bits.Add64(x138, x135, uint64(sm2p256Uint1(x146)))
	var x149 uint64
	var x150 uint64
	x149, x150 = bits.Add64(x127, x141, uint64(0x0))
	var x151 uint64
	var x152 uint64
	x151, x152 = bits.Add64(x129, x143, uint64(sm2p256Uint1(x150)))
	var x153 uint64
	var x154 uint64
	x153, x154 = bits.Add64(x131, x145, uint64(sm2p256Uint1(x152)))
	var x155 uint64
	var x156 uint64
	x155, x156 = bits.Add64(x133, x147, uint64(sm2p256Uint1(x154)))
	var x157 uint64
	var x158 uint64
	x158, x157 = bits.Mul64(x149, 0xfffffffeffffffff)
	var x159 uint64
	var x160 uint64
	x160, x159 = bits.Mul64(x149, 0xffffffffffffffff)
	var x161 uint64
	var x162 uint64
	x162, x161 = bits.Mul64(x149, 0xffffffff00000000)
	var x163 uint64
	var x164 uint64
	x164, x163 = bits.Mul64(x149, 0xffffffffffffffff)
	var x165 uint64
	var x166 uint64
	x165, x166 = bits.Add64(x164, x161, uint64(0x0))
	var x167 uint64
	var x168 uint64
	x167, x168 = bits.Add64(x162, x159, uint64(sm2p256Uint1(x166)))
	var x169 uint64
	var x170 uint64
	x169, x170 = bits.Add64(x160, x157, uint64(sm2p256Uint1(x168)))
	var x172 uint64
	_, x172 = bits.Add64(x149, x163, uint64(0x0))
	var x173 uint64
	var x174 uint64
	x173, x174 = bits.Add64(x151, x165, uint64(sm2p256Uint1(x172)))
	var x175 uint64
	var x176 uint64
	x175, x176 = bits.Add64(x153, x167, uint64(sm2p256Uint1(x174)))
	var x177 uint64
	var x178 uint64
	x177, x178 = bits.Add64(x155, x169, uint64(sm2p256Uint1(x176)))
	var x179 uint64
	var x180 uint64
	x179, x180 = bits.Add64(((uint64(sm2p256Uint1(x156)) + uint64(sm2p256Uint1(x134))) + (uint64(sm2p256Uint1(x148)) + x136)), (uint64(sm2p256Uint1(x170)) + x158), uint64(sm2p256Uint1(x178)))
	var x181 uint64
	var x182 uint64
	x181, x182 = bits.Sub64(x173, 0xffffffffffffffff, uint64(0x0))
	var x183 uint64
	var x184 uint64
	x183, x184 = bits.Sub64(x175, 0xffffffff00000000, uint64(sm2p256Uint1(x182)))
	var x185 uint64
	var x186 uint64
	x185, x186 = bits.Sub64(x177, 0xffffffffffffffff, uint64(sm2p256Uint1(x184)))
	var x187 uint64
	var x188 uint64
	x187, x188 = bits.Sub64(x179, 0xfffffffeffffffff, uint64(sm2p256Uint1(x186)))
	var x190 uint64
	_, x190 = bits.Sub64(uint64(sm2p256Uint1(x180)), uint64(0x0), uint64(sm2p256Uint1(x188)))
	var x191 uint64
	sm2p256CmovznzU64(&x191, sm2p256Uint1(x190), x181, x173)
	var x192 uint64
	sm2p256CmovznzU64(&x192, sm2p256Uint1(x190), x183, x175)
	var x193 uint64
	sm2p256CmovznzU64(&x193, sm2p256Uint1(x190), x185, x177)
	var x194 uint64
	sm2p256CmovznzU64(&x194, sm2p256Uint1(x190), x187, x179)
	out1[0] = x191
	out1[1] = x192
	out1[2] = x193
	out1[3] = x194
}

// sm2p256Selectznz is a multi-limb conditional select.
//
// Postconditions:
//
//	eval out1 = (if arg1 = 0 then eval arg2 else eval arg3)
//
// Input Bounds:
//
//	arg1: [0x0 ~> 0x1]
//	arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//	arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//
// Output Bounds:
//
//	out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func sm2p256Selectznz(out1 *[4]uint64, arg1 sm2p256Uint1, arg2 *[4]uint64, arg3 *[4]uint64) {
	var x1 uint64
	sm2p256CmovznzU64(&x1, arg1, arg2[0], arg3[0])
	var x2 uint64
	sm2p256CmovznzU64(&x2, arg1, arg2[1], arg3[1])
	var x3 uint64
	sm2p256CmovznzU64(&x3, arg1, arg2[2], arg3[2])
	var x4 uint64
	sm2p256CmovznzU64(&x4, arg1, arg2[3], arg3[3])
	out1[0] = x1
	out1[1] = x2
	out1[2] = x3
	out1[3] = x4
}

// sm2p256ToBytes serializes a field element NOT in the Montgomery domain to bytes in little-endian order.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	out1 = map (λ x, ⌊((eval arg1 mod m) mod 2^(8 * (x + 1))) / 2^(8 * x)⌋) [0..31]
//
// Input Bounds:
//
//	arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//
// Output Bounds:
//
//	out1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff]]
func sm2p256ToBytes(out1 *[32]uint8, arg1 *[4]uint64) {
	x1 := arg1[3]
	x2 := arg1[2]
	x3 := arg1[1]
	x4 := arg1[0]
	x5 := (uint8(x4) & 0xff)
	x6 := (x4 >> 8)
	x7 := (uint8(x6) & 0xff)
	x8 := (x6 >> 8)
	x9 := (uint8(x8) & 0xff)
	x10 := (x8 >> 8)
	x11 := (uint8(x10) & 0xff)
	x12 := (x10 >> 8)
	x13 := (uint8(x12) & 0xff)
	x14 := (x12 >> 8)
	x15 := (uint8(x14) & 0xff)
	x16 := (x14 >> 8)
	x17 := (uint8(x16) & 0xff)
	x18 := uint8((x16 >> 8))
	x19 := (uint8(x3) & 0xff)
	x20 := (x3 >> 8)
	x21 := (uint8(x20) & 0xff)
	x22 := (x20 >> 8)
	x23 := (uint8(x22) & 0xff)
	x24 := (x22 >> 8)
	x25 := (uint8(x24) & 0xff)
	x26 := (x24 >> 8)
	x27 := (uint8(x26) & 0xff)
	x28 := (x26 >> 8)
	x29 := (uint8(x28) & 0xff)
	x30 := (x28 >> 8)
	x31 := (uint8(x30) & 0xff)
	x32 := uint8((x30 >> 8))
	x33 := (uint8(x2) & 0xff)
	x34 := (x2 >> 8)
	x35 := (uint8(x34) & 0xff)
	x36 := (x34 >> 8)
	x37 := (uint8(x36) & 0xff)
	x38 := (x36 >> 8)
	x39 := (uint8(x38) & 0xff)
	x40 := (x38 >> 8)
	x41 := (uint8(x40) & 0xff)
	x42 := (x40 >> 8)
	x43 := (uint8(x42) & 0xff)
	x44 := (x42 >> 8)
	x45 := (uint8(x44) & 0xff)
	x46 := uint8((x44 >> 8))
	x47 := (uint8(x1) & 0xff)
	x48 := (x1 >> 8)
	x49 := (uint8(x48) & 0xff)
	x50 := (x48 >> 8)
	x51 := (uint8(x50) & 0xff)
	x52 := (x50 >> 8)
	x53 := (uint8(x52) & 0xff)
	x54 := (x52 >> 8)
	x55 := (uint8(x54) & 0xff)
	x56 := (x54 >> 8)
	x57 := (uint8(x56) & 0xff)
	x58 := (x56 >> 8)
	x59 := (uint8(x58) & 0xff)
	x60 := uint8((x58 >> 8))
	out1[0] = x5
	out1[1] = x7
	out1[2] = x9
	out1[3] = x11
	out1[4] = x13
	out1[5] = x15
	out1[6] = x17
	out1[7] = x18
	out1[8] = x19
	out1[9] = x21
	out1[10] = x23
	out1[11] = x25
	out1[12] = x27
	out1[13] = x29
	out1[14] = x31
	out1[15] = x32
	out1[16] = x33
	out1[17] = x35
	out1[18] = x37
	out1[19] = x39
	out1[20] = x41
	out1[21] = x43
	out1[22] = x45
	out1[23] = x46
	out1[24] = x47
	out1[25] = x49
	out1[26] = x51
	out1[27] = x53
	out1[28] = x55
	out1[29] = x57
	out1[30] = x59
	out1[31] = x60
}

// sm2p256FromBytes deserializes a field element NOT in the Montgomery domain from bytes in little-endian order.
//
// Preconditions:
//
//	0 ≤ bytes_eval arg1 < m
//
// Postconditions:
//
//	eval out1 mod m = bytes_eval arg1 mod m
//	0 ≤ eval out1 < m
//
// Input Bounds:
//
//	arg1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff]]
//
// Output Bounds:
//
//	out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func sm2p256FromBytes(out1 *[4]uint64, arg1 *[32]uint8) {
	x1 := (uint64(arg1[31]) << 56)
	x2 := (uint64(arg1[30]) << 48)
	x3 := (uint64(arg1[29]) << 40)
	x4 := (uint64(arg1[28]) << 32)
	x5 := (uint64(arg1[27]) << 24)
	x6 := (uint64(arg1[26]) << 16)
	x7 := (uint64(arg1[25]) << 8)
	x8 := arg1[24]
	x9 := (uint64(arg1[23]) << 56)
	x10 := (uint64(arg1[22]) << 48)
	x11 := (uint64(arg1[21]) << 40)
	x12 := (uint64(arg1[20]) << 32)
	x13 := (uint64(arg1[19]) << 24)
	x14 := (uint64(arg1[18]) << 16)
	x15 := (uint64(arg1[17]) << 8)
	x16 := arg1[16]
	x17 := (uint64(arg1[15]) << 56)
	x18 := (uint64(arg1[14]) << 48)
	x19 := (uint64(arg1[13]) << 40)
	x20 := (uint64(arg1[12]) << 32)
	x21 := (uint64(arg1[11]) << 24)
	x22 := (uint64(arg1[10]) << 16)
	x23 := (uint64(arg1[9]) << 8)
	x24 := arg1[8]
	x25 := (uint64(arg1[7]) << 56)
	x26 := (uint64(arg1[6]) << 48)
	x27 := (uint64(arg1[5]) << 40)
	x28 := (uint64(arg1[4]) << 32)
	x29 := (uint64(arg1[3]) << 24)
	x30 := (uint64(arg1[2]) << 16)
	x31 := (uint64(arg1[1]) << 8)
	x32 := arg1[0]
	x33 := (x31 + uint64(x32))
	x34 := (x30 + x33)
	x35 := (x29 + x34)
	x36 := (x28 + x35)
	x37 := (x27 + x36)
	x38 := (x26 + x37)
	x39 := (x25 + x38)
	x40 := (x23 + uint64(x24))
	x41 := (x22 + x40)
	x42 := (x21 + x41)
	x43 := (x20 + x42)
	x44 := (x19 + x43)
	x45 := (x18 + x44)
	x46 := (x17 + x45)
	x47 := (x15 + uint64(x16))
	x48 := (x14 + x47)
	x49 := (x13 + x48)
	x50 := (x12 + x49)
	x51 := (x11 + x50)
	x52 := (x10 + x51)
	x53 := (x9 + x52)
	x54 := (x7 + uint64(x8))
	x55 := (x6 + x54)
	x56 := (x5 + x55)
	x57 := (x4 + x56)
	x58 := (x3 + x57)
	x59 := (x2 + x58)
	x60 := (x1 + x59)
	out1[0] = x39
	out1[1] = x46
	out1[2] = x53
	out1[3] = x60
}
