package gmsm

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"time"
)

// Tag represents an ASN.1 identifier octet, consisting of a tag number
// (indicating a type) and class (such as context-specific or constructed).
//
// Methods in the cryptobyte package only support the low-tag-number form, i.e.
// a single identifier octet with bits 7-8 encoding the class and bits 1-6
// encoding the tag number.
type Tag uint8

const (
	classConstructed     = 0x20
	classContextSpecific = 0x80
)

// Constructed returns t with the constructed class bit set.
func (t Tag) Constructed() Tag { return t | classConstructed }

// ContextSpecific returns t with the context-specific class bit set.
func (t Tag) ContextSpecific() Tag { return t | classContextSpecific }

// The following is a list of standard tag and class combinations.
const (
	BOOLEAN           = Tag(1)
	INTEGER           = Tag(2)
	BIT_STRING        = Tag(3)
	OCTET_STRING      = Tag(4)
	NULL              = Tag(5)
	OBJECT_IDENTIFIER = Tag(6)
	ENUM              = Tag(10)
	UTF8String        = Tag(12)
	SEQUENCE          = Tag(16 | classConstructed)
	SET               = Tag(17 | classConstructed)
	PrintableString   = Tag(19)
	T61String         = Tag(20)
	IA5String         = Tag(22)
	UTCTime           = Tag(23)
	GeneralizedTime   = Tag(24)
	GeneralString     = Tag(27)
)

// A Builder builds byte strings from fixed-length and length-prefixed values.
// Builders either allocate space as needed, or are ‘fixed’, which means that
// they write into a given buffer and produce an error if it's exhausted.
//
// The zero value is a usable Builder that allocates space as needed.
//
// Simple values are marshaled and appended to a Builder using methods on the
// Builder. Length-prefixed values are marshaled by providing a
// BuilderContinuation, which is a function that writes the inner contents of
// the value to a given Builder. See the documentation for BuilderContinuation
// for details.
type Builder struct {
	err            error
	result         []byte
	fixedSize      bool
	child          *Builder
	offset         int
	pendingLenLen  int
	pendingIsASN1  bool
	inContinuation *bool
}

// NewBuilder creates a Builder that appends its output to the given buffer.
// Like append(), the slice will be reallocated if its capacity is exceeded.
// Use Bytes to get the final buffer.
func NewBuilder(buffer []byte) *Builder {
	return &Builder{
		result: buffer,
	}
}

// NewFixedBuilder creates a Builder that appends its output into the given
// buffer. This builder does not reallocate the output buffer. Writes that
// would exceed the buffer's capacity are treated as an error.
func NewFixedBuilder(buffer []byte) *Builder {
	return &Builder{
		result:    buffer,
		fixedSize: true,
	}
}

// SetError sets the value to be returned as the error from Bytes. Writes
// performed after calling SetError are ignored.
func (b *Builder) SetError(err error) {
	b.err = err
}

// Bytes returns the bytes written by the builder or an error if one has
// occurred during building.
func (b *Builder) Bytes() ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.result[b.offset:], nil
}

// BytesOrPanic returns the bytes written by the builder or panics if an error
// has occurred during building.
func (b *Builder) BytesOrPanic() []byte {
	if b.err != nil {
		panic(b.err)
	}
	return b.result[b.offset:]
}

// AddUint8 appends an 8-bit value to the byte string.
func (b *Builder) AddUint8(v uint8) {
	b.add(byte(v))
}

// AddUint16 appends a big-endian, 16-bit value to the byte string.
func (b *Builder) AddUint16(v uint16) {
	b.add(byte(v>>8), byte(v))
}

// AddUint24 appends a big-endian, 24-bit value to the byte string. The highest
// byte of the 32-bit input value is silently truncated.
func (b *Builder) AddUint24(v uint32) {
	b.add(byte(v>>16), byte(v>>8), byte(v))
}

// AddUint32 appends a big-endian, 32-bit value to the byte string.
func (b *Builder) AddUint32(v uint32) {
	b.add(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// AddUint48 appends a big-endian, 48-bit value to the byte string.
func (b *Builder) AddUint48(v uint64) {
	b.add(byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// AddUint64 appends a big-endian, 64-bit value to the byte string.
func (b *Builder) AddUint64(v uint64) {
	b.add(byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// AddBytes appends a sequence of bytes to the byte string.
func (b *Builder) AddBytes(v []byte) {
	b.add(v...)
}

// BuilderContinuation is a continuation-passing interface for building
// length-prefixed byte sequences. Builder methods for length-prefixed
// sequences (AddUint8LengthPrefixed etc) will invoke the BuilderContinuation
// supplied to them. The child builder passed to the continuation can be used
// to build the content of the length-prefixed sequence. For example:
//
//	parent := cryptobyte.NewBuilder()
//	parent.AddUint8LengthPrefixed(func (child *Builder) {
//	  child.AddUint8(42)
//	  child.AddUint8LengthPrefixed(func (grandchild *Builder) {
//	    grandchild.AddUint8(5)
//	  })
//	})
//
// It is an error to write more bytes to the child than allowed by the reserved
// length prefix. After the continuation returns, the child must be considered
// invalid, i.e. users must not store any copies or references of the child
// that outlive the continuation.
//
// If the continuation panics with a value of type BuildError then the inner
// error will be returned as the error from Bytes. If the child panics
// otherwise then Bytes will repanic with the same value.
type BuilderContinuation func(child *Builder)

// BuildError wraps an error. If a BuilderContinuation panics with this value,
// the panic will be recovered and the inner error will be returned from
// Builder.Bytes.
type BuildError struct {
	Err error
}

// AddUint8LengthPrefixed adds a 8-bit length-prefixed byte sequence.
func (b *Builder) AddUint8LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(1, false, f)
}

// AddUint16LengthPrefixed adds a big-endian, 16-bit length-prefixed byte sequence.
func (b *Builder) AddUint16LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(2, false, f)
}

// AddUint24LengthPrefixed adds a big-endian, 24-bit length-prefixed byte sequence.
func (b *Builder) AddUint24LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(3, false, f)
}

// AddUint32LengthPrefixed adds a big-endian, 32-bit length-prefixed byte sequence.
func (b *Builder) AddUint32LengthPrefixed(f BuilderContinuation) {
	b.addLengthPrefixed(4, false, f)
}

func (b *Builder) callContinuation(f BuilderContinuation, arg *Builder) {
	if !*b.inContinuation {
		*b.inContinuation = true

		defer func() {
			*b.inContinuation = false

			r := recover()
			if r == nil {
				return
			}

			if buildError, ok := r.(BuildError); ok {
				b.err = buildError.Err
			} else {
				panic(r)
			}
		}()
	}

	f(arg)
}

func (b *Builder) addLengthPrefixed(lenLen int, isASN1 bool, f BuilderContinuation) {
	// Subsequent writes can be ignored if the builder has encountered an error.
	if b.err != nil {
		return
	}

	offset := len(b.result)
	b.add(make([]byte, lenLen)...)

	if b.inContinuation == nil {
		b.inContinuation = new(bool)
	}

	b.child = &Builder{
		result:         b.result,
		fixedSize:      b.fixedSize,
		offset:         offset,
		pendingLenLen:  lenLen,
		pendingIsASN1:  isASN1,
		inContinuation: b.inContinuation,
	}

	b.callContinuation(f, b.child)
	b.flushChild()
	if b.child != nil {
		panic("cryptobyte: internal error")
	}
}

func (b *Builder) flushChild() {
	if b.child == nil {
		return
	}
	b.child.flushChild()
	child := b.child
	b.child = nil

	if child.err != nil {
		b.err = child.err
		return
	}

	length := len(child.result) - child.pendingLenLen - child.offset

	if length < 0 {
		panic("cryptobyte: internal error") // result unexpectedly shrunk
	}

	if child.pendingIsASN1 {
		// For ASN.1, we reserved a single byte for the length. If that turned out
		// to be incorrect, we have to move the contents along in order to make
		// space.
		if child.pendingLenLen != 1 {
			panic("cryptobyte: internal error")
		}
		var lenLen, lenByte uint8
		if int64(length) > 0xfffffffe {
			b.err = errors.New("pending ASN.1 child too long")
			return
		} else if length > 0xffffff {
			lenLen = 5
			lenByte = 0x80 | 4
		} else if length > 0xffff {
			lenLen = 4
			lenByte = 0x80 | 3
		} else if length > 0xff {
			lenLen = 3
			lenByte = 0x80 | 2
		} else if length > 0x7f {
			lenLen = 2
			lenByte = 0x80 | 1
		} else {
			lenLen = 1
			lenByte = uint8(length)
			length = 0
		}

		// Insert the initial length byte, make space for successive length bytes,
		// and adjust the offset.
		child.result[child.offset] = lenByte
		extraBytes := int(lenLen - 1)
		if extraBytes != 0 {
			child.add(make([]byte, extraBytes)...)
			childStart := child.offset + child.pendingLenLen
			copy(child.result[childStart+extraBytes:], child.result[childStart:])
		}
		child.offset++
		child.pendingLenLen = extraBytes
	}

	l := length
	for i := child.pendingLenLen - 1; i >= 0; i-- {
		child.result[child.offset+i] = uint8(l)
		l >>= 8
	}
	if l != 0 {
		b.err = fmt.Errorf("cryptobyte: pending child length %d exceeds %d-byte length prefix", length, child.pendingLenLen)
		return
	}

	if b.fixedSize && &b.result[0] != &child.result[0] {
		panic("cryptobyte: BuilderContinuation reallocated a fixed-size buffer")
	}

	b.result = child.result
}

func (b *Builder) add(bytes ...byte) {
	if b.err != nil {
		return
	}
	if b.child != nil {
		panic("cryptobyte: attempted write while child is pending")
	}
	if len(b.result)+len(bytes) < len(bytes) {
		b.err = errors.New("cryptobyte: length overflow")
	}
	if b.fixedSize && len(b.result)+len(bytes) > cap(b.result) {
		b.err = errors.New("cryptobyte: Builder is exceeding its fixed-size buffer")
		return
	}
	b.result = append(b.result, bytes...)
}

// Unwrite rolls back non-negative n bytes written directly to the Builder.
// An attempt by a child builder passed to a continuation to unwrite bytes
// from its parent will panic.
func (b *Builder) Unwrite(n int) {
	if b.err != nil {
		return
	}
	if b.child != nil {
		panic("cryptobyte: attempted unwrite while child is pending")
	}
	length := len(b.result) - b.pendingLenLen - b.offset
	if length < 0 {
		panic("cryptobyte: internal error")
	}
	if n < 0 {
		panic("cryptobyte: attempted to unwrite negative number of bytes")
	}
	if n > length {
		panic("cryptobyte: attempted to unwrite more than was written")
	}
	b.result = b.result[:len(b.result)-n]
}

// A MarshalingValue marshals itself into a Builder.
type MarshalingValue interface {
	// Marshal is called by Builder.AddValue. It receives a pointer to a builder
	// to marshal itself into. It may return an error that occurred during
	// marshaling, such as unset or invalid values.
	Marshal(b *Builder) error
}

// AddValue calls Marshal on v, passing a pointer to the builder to append to.
// If Marshal returns an error, it is set on the Builder so that subsequent
// appends don't have an effect.
func (b *Builder) AddValue(v MarshalingValue) {
	err := v.Marshal(b)
	if err != nil {
		b.err = err
	}
}

// This file contains ASN.1-related methods for String and Builder.

// Builder

// AddASN1Int64 appends a DER-encoded ASN.1 INTEGER.
func (b *Builder) AddASN1Int64(v int64) {
	b.addASN1Signed(INTEGER, v)
}

// AddASN1Int64WithTag appends a DER-encoded ASN.1 INTEGER with the
// given tag.
func (b *Builder) AddASN1Int64WithTag(v int64, tag Tag) {
	b.addASN1Signed(tag, v)
}

// AddASN1Enum appends a DER-encoded ASN.1 ENUMERATION.
func (b *Builder) AddASN1Enum(v int64) {
	b.addASN1Signed(ENUM, v)
}

func (b *Builder) addASN1Signed(tag Tag, v int64) {
	b.AddASN1(tag, func(c *Builder) {
		length := 1
		for i := v; i >= 0x80 || i < -0x80; i >>= 8 {
			length++
		}

		for ; length > 0; length-- {
			i := v >> uint((length-1)*8) & 0xff
			c.AddUint8(uint8(i))
		}
	})
}

// AddASN1Uint64 appends a DER-encoded ASN.1 INTEGER.
func (b *Builder) AddASN1Uint64(v uint64) {
	b.AddASN1(INTEGER, func(c *Builder) {
		length := 1
		for i := v; i >= 0x80; i >>= 8 {
			length++
		}

		for ; length > 0; length-- {
			i := v >> uint((length-1)*8) & 0xff
			c.AddUint8(uint8(i))
		}
	})
}

// AddASN1BigInt appends a DER-encoded ASN.1 INTEGER.
func (b *Builder) AddASN1BigInt(n *big.Int) {
	if b.err != nil {
		return
	}

	b.AddASN1(INTEGER, func(c *Builder) {
		if n.Sign() < 0 {
			// A negative number has to be converted to two's-complement form. So we
			// invert and subtract 1. If the most-significant-bit isn't set then
			// we'll need to pad the beginning with 0xff in order to keep the number
			// negative.
			nMinus1 := new(big.Int).Neg(n)
			nMinus1.Sub(nMinus1, bigOne)
			bytes := nMinus1.Bytes()
			for i := range bytes {
				bytes[i] ^= 0xff
			}
			if len(bytes) == 0 || bytes[0]&0x80 == 0 {
				c.add(0xff)
			}
			c.add(bytes...)
		} else if n.Sign() == 0 {
			c.add(0)
		} else {
			bytes := n.Bytes()
			if bytes[0]&0x80 != 0 {
				c.add(0)
			}
			c.add(bytes...)
		}
	})
}

// AddASN1OctetString appends a DER-encoded ASN.1 OCTET STRING.
func (b *Builder) AddASN1OctetString(bytes []byte) {
	b.AddASN1(OCTET_STRING, func(c *Builder) {
		c.AddBytes(bytes)
	})
}

const generalizedTimeFormatStr = "20060102150405Z0700"

// AddASN1GeneralizedTime appends a DER-encoded ASN.1 GENERALIZEDTIME.
func (b *Builder) AddASN1GeneralizedTime(t time.Time) {
	if t.Year() < 0 || t.Year() > 9999 {
		b.err = fmt.Errorf("cryptobyte: cannot represent %v as a GeneralizedTime", t)
		return
	}
	b.AddASN1(GeneralizedTime, func(c *Builder) {
		c.AddBytes([]byte(t.Format(generalizedTimeFormatStr)))
	})
}

// AddASN1UTCTime appends a DER-encoded ASN.1 UTCTime.
func (b *Builder) AddASN1UTCTime(t time.Time) {
	b.AddASN1(UTCTime, func(c *Builder) {
		// As utilized by the X.509 profile, UTCTime can only
		// represent the years 1950 through 2049.
		if t.Year() < 1950 || t.Year() >= 2050 {
			b.err = fmt.Errorf("cryptobyte: cannot represent %v as a UTCTime", t)
			return
		}
		c.AddBytes([]byte(t.Format(defaultUTCTimeFormatStr)))
	})
}

// AddASN1BitString appends a DER-encoded ASN.1 BIT STRING. This does not
// support BIT STRINGs that are not a whole number of bytes.
func (b *Builder) AddASN1BitString(data []byte) {
	b.AddASN1(BIT_STRING, func(b *Builder) {
		b.AddUint8(0)
		b.AddBytes(data)
	})
}

func (b *Builder) addBase128Int(n int64) {
	var length int
	if n == 0 {
		length = 1
	} else {
		for i := n; i > 0; i >>= 7 {
			length++
		}
	}

	for i := length - 1; i >= 0; i-- {
		o := byte(n >> uint(i*7))
		o &= 0x7f
		if i != 0 {
			o |= 0x80
		}

		b.add(o)
	}
}

func isValidOID(oid asn1.ObjectIdentifier) bool {
	if len(oid) < 2 {
		return false
	}

	if oid[0] > 2 || (oid[0] <= 1 && oid[1] >= 40) {
		return false
	}

	for _, v := range oid {
		if v < 0 {
			return false
		}
	}

	return true
}

func (b *Builder) AddASN1ObjectIdentifier(oid asn1.ObjectIdentifier) {
	b.AddASN1(OBJECT_IDENTIFIER, func(b *Builder) {
		if !isValidOID(oid) {
			b.err = fmt.Errorf("cryptobyte: invalid OID: %v", oid)
			return
		}

		b.addBase128Int(int64(oid[0])*40 + int64(oid[1]))
		for _, v := range oid[2:] {
			b.addBase128Int(int64(v))
		}
	})
}

func (b *Builder) AddASN1Boolean(v bool) {
	b.AddASN1(BOOLEAN, func(b *Builder) {
		if v {
			b.AddUint8(0xff)
		} else {
			b.AddUint8(0)
		}
	})
}

func (b *Builder) AddASN1NULL() {
	b.add(uint8(NULL), 0)
}

// MarshalASN1 calls encoding_asn1.Marshal on its input and appends the result if
// successful or records an error if one occurred.
func (b *Builder) MarshalASN1(v interface{}) {
	// NOTE(martinkr): This is somewhat of a hack to allow propagation of
	// encoding_asn1.Marshal errors into Builder.err. N.B. if you call MarshalASN1 with a
	// value embedded into a struct, its tag information is lost.
	if b.err != nil {
		return
	}
	bytes, err := asn1.Marshal(v)
	if err != nil {
		b.err = err
		return
	}
	b.AddBytes(bytes)
}

// AddASN1 appends an ASN.1 object. The object is prefixed with the given tag.
// Tags greater than 30 are not supported and result in an error (i.e.
// low-tag-number form only). The child builder passed to the
// BuilderContinuation can be used to build the content of the ASN.1 object.
func (b *Builder) AddASN1(tag Tag, f BuilderContinuation) {
	if b.err != nil {
		return
	}
	// Identifiers with the low five bits set indicate high-tag-number format
	// (two or more octets), which we don't support.
	if tag&0x1f == 0x1f {
		b.err = fmt.Errorf("cryptobyte: high-tag number identifier octects not supported: 0x%x", tag)
		return
	}
	b.AddUint8(uint8(tag))
	b.addLengthPrefixed(1, true, f)
}

// String

// String represents a string of bytes. It provides methods for parsing
// fixed-length and length-prefixed values from it.
type String []byte

// read advances a String by n bytes and returns them. If less than n bytes
// remain, it returns nil.
func (s *String) read(n int) []byte {
	if len(*s) < n || n < 0 {
		return nil
	}
	v := (*s)[:n]
	*s = (*s)[n:]
	return v
}

// Skip advances the String by n byte and reports whether it was successful.
func (s *String) Skip(n int) bool {
	return s.read(n) != nil
}

// ReadUint8 decodes an 8-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint8(out *uint8) bool {
	v := s.read(1)
	if v == nil {
		return false
	}
	*out = uint8(v[0])
	return true
}

// ReadUint16 decodes a big-endian, 16-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint16(out *uint16) bool {
	v := s.read(2)
	if v == nil {
		return false
	}
	*out = uint16(v[0])<<8 | uint16(v[1])
	return true
}

// ReadUint24 decodes a big-endian, 24-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint24(out *uint32) bool {
	v := s.read(3)
	if v == nil {
		return false
	}
	*out = uint32(v[0])<<16 | uint32(v[1])<<8 | uint32(v[2])
	return true
}

// ReadUint32 decodes a big-endian, 32-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint32(out *uint32) bool {
	v := s.read(4)
	if v == nil {
		return false
	}
	*out = uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	return true
}

// ReadUint48 decodes a big-endian, 48-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint48(out *uint64) bool {
	v := s.read(6)
	if v == nil {
		return false
	}
	*out = uint64(v[0])<<40 | uint64(v[1])<<32 | uint64(v[2])<<24 | uint64(v[3])<<16 | uint64(v[4])<<8 | uint64(v[5])
	return true
}

// ReadUint64 decodes a big-endian, 64-bit value into out and advances over it.
// It reports whether the read was successful.
func (s *String) ReadUint64(out *uint64) bool {
	v := s.read(8)
	if v == nil {
		return false
	}
	*out = uint64(v[0])<<56 | uint64(v[1])<<48 | uint64(v[2])<<40 | uint64(v[3])<<32 | uint64(v[4])<<24 | uint64(v[5])<<16 | uint64(v[6])<<8 | uint64(v[7])
	return true
}

func (s *String) readUnsigned(out *uint32, length int) bool {
	v := s.read(length)
	if v == nil {
		return false
	}
	var result uint32
	for i := 0; i < length; i++ {
		result <<= 8
		result |= uint32(v[i])
	}
	*out = result
	return true
}

func (s *String) readLengthPrefixed(lenLen int, outChild *String) bool {
	lenBytes := s.read(lenLen)
	if lenBytes == nil {
		return false
	}
	var length uint32
	for _, b := range lenBytes {
		length = length << 8
		length = length | uint32(b)
	}
	v := s.read(int(length))
	if v == nil {
		return false
	}
	*outChild = v
	return true
}

// ReadUint8LengthPrefixed reads the content of an 8-bit length-prefixed value
// into out and advances over it. It reports whether the read was successful.
func (s *String) ReadUint8LengthPrefixed(out *String) bool {
	return s.readLengthPrefixed(1, out)
}

// ReadUint16LengthPrefixed reads the content of a big-endian, 16-bit
// length-prefixed value into out and advances over it. It reports whether the
// read was successful.
func (s *String) ReadUint16LengthPrefixed(out *String) bool {
	return s.readLengthPrefixed(2, out)
}

// ReadUint24LengthPrefixed reads the content of a big-endian, 24-bit
// length-prefixed value into out and advances over it. It reports whether
// the read was successful.
func (s *String) ReadUint24LengthPrefixed(out *String) bool {
	return s.readLengthPrefixed(3, out)
}

// ReadBytes reads n bytes into out and advances over them. It reports
// whether the read was successful.
func (s *String) ReadBytes(out *[]byte, n int) bool {
	v := s.read(n)
	if v == nil {
		return false
	}
	*out = v
	return true
}

// CopyBytes copies len(out) bytes into out and advances over them. It reports
// whether the copy operation was successful
func (s *String) CopyBytes(out []byte) bool {
	n := len(out)
	v := s.read(n)
	if v == nil {
		return false
	}
	return copy(out, v) == n
}

// Empty reports whether the string does not contain any bytes.
func (s String) Empty() bool {
	return len(s) == 0
}

// ReadASN1Boolean decodes an ASN.1 BOOLEAN and converts it to a boolean
// representation into out and advances. It reports whether the read
// was successful.
func (s *String) ReadASN1Boolean(out *bool) bool {
	var bytes String
	if !s.ReadASN1(&bytes, BOOLEAN) || len(bytes) != 1 {
		return false
	}

	switch bytes[0] {
	case 0:
		*out = false
	case 0xff:
		*out = true
	default:
		return false
	}

	return true
}

// ReadASN1Integer decodes an ASN.1 INTEGER into out and advances. If out does
// not point to an integer, to a big.Int, or to a []byte it panics. Only
// positive and zero values can be decoded into []byte, and they are returned as
// big-endian binary values that share memory with s. Positive values will have
// no leading zeroes, and zero will be returned as a single zero byte.
// ReadASN1Integer reports whether the read was successful.
func (s *String) ReadASN1Integer(out interface{}) bool {
	switch out := out.(type) {
	case *int, *int8, *int16, *int32, *int64:
		var i int64
		if !s.readASN1Int64(&i) || reflect.ValueOf(out).Elem().OverflowInt(i) {
			return false
		}
		reflect.ValueOf(out).Elem().SetInt(i)
		return true
	case *uint, *uint8, *uint16, *uint32, *uint64:
		var u uint64
		if !s.readASN1Uint64(&u) || reflect.ValueOf(out).Elem().OverflowUint(u) {
			return false
		}
		reflect.ValueOf(out).Elem().SetUint(u)
		return true
	case *big.Int:
		return s.readASN1BigInt(out)
	case *[]byte:
		return s.readASN1Bytes(out)
	default:
		panic("out does not point to an integer type")
	}
}

func checkASN1Integer(bytes []byte) bool {
	if len(bytes) == 0 {
		// An INTEGER is encoded with at least one octet.
		return false
	}
	if len(bytes) == 1 {
		return true
	}
	if bytes[0] == 0 && bytes[1]&0x80 == 0 || bytes[0] == 0xff && bytes[1]&0x80 == 0x80 {
		// Value is not minimally encoded.
		return false
	}
	return true
}

var bigOne = big.NewInt(1)

func (s *String) readASN1BigInt(out *big.Int) bool {
	var bytes String
	if !s.ReadASN1(&bytes, INTEGER) || !checkASN1Integer(bytes) {
		return false
	}
	if bytes[0]&0x80 == 0x80 {
		// Negative number.
		neg := make([]byte, len(bytes))
		for i, b := range bytes {
			neg[i] = ^b
		}
		out.SetBytes(neg)
		out.Add(out, bigOne)
		out.Neg(out)
	} else {
		out.SetBytes(bytes)
	}
	return true
}

func (s *String) readASN1Bytes(out *[]byte) bool {
	var bytes String
	if !s.ReadASN1(&bytes, INTEGER) || !checkASN1Integer(bytes) {
		return false
	}
	if bytes[0]&0x80 == 0x80 {
		return false
	}
	for len(bytes) > 1 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	*out = bytes
	return true
}

func (s *String) readASN1Int64(out *int64) bool {
	var bytes String
	if !s.ReadASN1(&bytes, INTEGER) || !checkASN1Integer(bytes) || !asn1Signed(out, bytes) {
		return false
	}
	return true
}

func asn1Signed(out *int64, n []byte) bool {
	length := len(n)
	if length > 8 {
		return false
	}
	for i := 0; i < length; i++ {
		*out <<= 8
		*out |= int64(n[i])
	}
	// Shift up and down in order to sign extend the result.
	*out <<= 64 - uint8(length)*8
	*out >>= 64 - uint8(length)*8
	return true
}

func (s *String) readASN1Uint64(out *uint64) bool {
	var bytes String
	if !s.ReadASN1(&bytes, INTEGER) || !checkASN1Integer(bytes) || !asn1Unsigned(out, bytes) {
		return false
	}
	return true
}

func asn1Unsigned(out *uint64, n []byte) bool {
	length := len(n)
	if length > 9 || length == 9 && n[0] != 0 {
		// Too large for uint64.
		return false
	}
	if n[0]&0x80 != 0 {
		// Negative number.
		return false
	}
	for i := 0; i < length; i++ {
		*out <<= 8
		*out |= uint64(n[i])
	}
	return true
}

// ReadASN1Int64WithTag decodes an ASN.1 INTEGER with the given tag into out
// and advances. It reports whether the read was successful and resulted in a
// value that can be represented in an int64.
func (s *String) ReadASN1Int64WithTag(out *int64, tag Tag) bool {
	var bytes String
	return s.ReadASN1(&bytes, tag) && checkASN1Integer(bytes) && asn1Signed(out, bytes)
}

// ReadASN1Enum decodes an ASN.1 ENUMERATION into out and advances. It reports
// whether the read was successful.
func (s *String) ReadASN1Enum(out *int) bool {
	var bytes String
	var i int64
	if !s.ReadASN1(&bytes, ENUM) || !checkASN1Integer(bytes) || !asn1Signed(&i, bytes) {
		return false
	}
	if int64(int(i)) != i {
		return false
	}
	*out = int(i)
	return true
}

func (s *String) readBase128Int(out *int) bool {
	ret := 0
	for i := 0; len(*s) > 0; i++ {
		if i == 5 {
			return false
		}
		// Avoid overflowing int on a 32-bit platform.
		// We don't want different behavior based on the architecture.
		if ret >= 1<<(31-7) {
			return false
		}
		ret <<= 7
		b := s.read(1)[0]

		// ITU-T X.690, section 8.19.2:
		// The subidentifier shall be encoded in the fewest possible octets,
		// that is, the leading octet of the subidentifier shall not have the value 0x80.
		if i == 0 && b == 0x80 {
			return false
		}

		ret |= int(b & 0x7f)
		if b&0x80 == 0 {
			*out = ret
			return true
		}
	}
	return false // truncated
}

// ReadASN1ObjectIdentifier decodes an ASN.1 OBJECT IDENTIFIER into out and
// advances. It reports whether the read was successful.
func (s *String) ReadASN1ObjectIdentifier(out *asn1.ObjectIdentifier) bool {
	var bytes String
	if !s.ReadASN1(&bytes, OBJECT_IDENTIFIER) || len(bytes) == 0 {
		return false
	}

	// In the worst case, we get two elements from the first byte (which is
	// encoded differently) and then every varint is a single byte long.
	components := make([]int, len(bytes)+1)

	// The first varint is 40*value1 + value2:
	// According to this packing, value1 can take the values 0, 1 and 2 only.
	// When value1 = 0 or value1 = 1, then value2 is <= 39. When value1 = 2,
	// then there are no restrictions on value2.
	var v int
	if !bytes.readBase128Int(&v) {
		return false
	}
	if v < 80 {
		components[0] = v / 40
		components[1] = v % 40
	} else {
		components[0] = 2
		components[1] = v - 80
	}

	i := 2
	for ; len(bytes) > 0; i++ {
		if !bytes.readBase128Int(&v) {
			return false
		}
		components[i] = v
	}
	*out = components[:i]
	return true
}

// ReadASN1GeneralizedTime decodes an ASN.1 GENERALIZEDTIME into out and
// advances. It reports whether the read was successful.
func (s *String) ReadASN1GeneralizedTime(out *time.Time) bool {
	var bytes String
	if !s.ReadASN1(&bytes, GeneralizedTime) {
		return false
	}
	t := string(bytes)
	res, err := time.Parse(generalizedTimeFormatStr, t)
	if err != nil {
		return false
	}
	if serialized := res.Format(generalizedTimeFormatStr); serialized != t {
		return false
	}
	*out = res
	return true
}

const defaultUTCTimeFormatStr = "060102150405Z0700"

// ReadASN1UTCTime decodes an ASN.1 UTCTime into out and advances.
// It reports whether the read was successful.
func (s *String) ReadASN1UTCTime(out *time.Time) bool {
	var bytes String
	if !s.ReadASN1(&bytes, UTCTime) {
		return false
	}
	t := string(bytes)

	formatStr := defaultUTCTimeFormatStr
	var err error
	res, err := time.Parse(formatStr, t)
	if err != nil {
		// Fallback to minute precision if we can't parse second
		// precision. If we are following X.509 or X.690 we shouldn't
		// support this, but we do.
		formatStr = "0601021504Z0700"
		res, err = time.Parse(formatStr, t)
	}
	if err != nil {
		return false
	}

	if serialized := res.Format(formatStr); serialized != t {
		return false
	}

	if res.Year() >= 2050 {
		// UTCTime interprets the low order digits 50-99 as 1950-99.
		// This only applies to its use in the X.509 profile.
		// See https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
		res = res.AddDate(-100, 0, 0)
	}
	*out = res
	return true
}

// ReadASN1BitString decodes an ASN.1 BIT STRING into out and advances.
// It reports whether the read was successful.
func (s *String) ReadASN1BitString(out *asn1.BitString) bool {
	var bytes String
	if !s.ReadASN1(&bytes, BIT_STRING) || len(bytes) == 0 ||
		len(bytes)*8/8 != len(bytes) {
		return false
	}

	paddingBits := bytes[0]
	bytes = bytes[1:]
	if paddingBits > 7 ||
		len(bytes) == 0 && paddingBits != 0 ||
		len(bytes) > 0 && bytes[len(bytes)-1]&(1<<paddingBits-1) != 0 {
		return false
	}

	out.BitLength = len(bytes)*8 - int(paddingBits)
	out.Bytes = bytes
	return true
}

// ReadASN1BitStringAsBytes decodes an ASN.1 BIT STRING into out and advances. It is
// an error if the BIT STRING is not a whole number of bytes. It reports
// whether the read was successful.
func (s *String) ReadASN1BitStringAsBytes(out *[]byte) bool {
	var bytes String
	if !s.ReadASN1(&bytes, BIT_STRING) || len(bytes) == 0 {
		return false
	}

	paddingBits := bytes[0]
	if paddingBits != 0 {
		return false
	}
	*out = bytes[1:]
	return true
}

// ReadASN1Bytes reads the contents of a DER-encoded ASN.1 element (not including
// tag and length bytes) into out, and advances. The element must match the
// given tag. It reports whether the read was successful.
func (s *String) ReadASN1Bytes(out *[]byte, tag Tag) bool {
	return s.ReadASN1((*String)(out), tag)
}

// ReadASN1 reads the contents of a DER-encoded ASN.1 element (not including
// tag and length bytes) into out, and advances. The element must match the
// given tag. It reports whether the read was successful.
//
// Tags greater than 30 are not supported (i.e. low-tag-number format only).
func (s *String) ReadASN1(out *String, tag Tag) bool {
	var t Tag
	if !s.ReadAnyASN1(out, &t) || t != tag {
		return false
	}
	return true
}

// ReadASN1Element reads the contents of a DER-encoded ASN.1 element (including
// tag and length bytes) into out, and advances. The element must match the
// given tag. It reports whether the read was successful.
//
// Tags greater than 30 are not supported (i.e. low-tag-number format only).
func (s *String) ReadASN1Element(out *String, tag Tag) bool {
	var t Tag
	if !s.ReadAnyASN1Element(out, &t) || t != tag {
		return false
	}
	return true
}

// ReadAnyASN1 reads the contents of a DER-encoded ASN.1 element (not including
// tag and length bytes) into out, sets outTag to its tag, and advances.
// It reports whether the read was successful.
//
// Tags greater than 30 are not supported (i.e. low-tag-number format only).
func (s *String) ReadAnyASN1(out *String, outTag *Tag) bool {
	return s.readASN1(out, outTag, true /* skip header */)
}

// ReadAnyASN1Element reads the contents of a DER-encoded ASN.1 element
// (including tag and length bytes) into out, sets outTag to is tag, and
// advances. It reports whether the read was successful.
//
// Tags greater than 30 are not supported (i.e. low-tag-number format only).
func (s *String) ReadAnyASN1Element(out *String, outTag *Tag) bool {
	return s.readASN1(out, outTag, false /* include header */)
}

// PeekASN1Tag reports whether the next ASN.1 value on the string starts with
// the given tag.
func (s String) PeekASN1Tag(tag Tag) bool {
	if len(s) == 0 {
		return false
	}
	return Tag(s[0]) == tag
}

// SkipASN1 reads and discards an ASN.1 element with the given tag. It
// reports whether the operation was successful.
func (s *String) SkipASN1(tag Tag) bool {
	var unused String
	return s.ReadASN1(&unused, tag)
}

// ReadOptionalASN1 attempts to read the contents of a DER-encoded ASN.1
// element (not including tag and length bytes) tagged with the given tag into
// out. It stores whether an element with the tag was found in outPresent,
// unless outPresent is nil. It reports whether the read was successful.
func (s *String) ReadOptionalASN1(out *String, outPresent *bool, tag Tag) bool {
	present := s.PeekASN1Tag(tag)
	if outPresent != nil {
		*outPresent = present
	}
	if present && !s.ReadASN1(out, tag) {
		return false
	}
	return true
}

// SkipOptionalASN1 advances s over an ASN.1 element with the given tag, or
// else leaves s unchanged. It reports whether the operation was successful.
func (s *String) SkipOptionalASN1(tag Tag) bool {
	if !s.PeekASN1Tag(tag) {
		return true
	}
	var unused String
	return s.ReadASN1(&unused, tag)
}

// ReadOptionalASN1Integer attempts to read an optional ASN.1 INTEGER explicitly
// tagged with tag into out and advances. If no element with a matching tag is
// present, it writes defaultValue into out instead. Otherwise, it behaves like
// ReadASN1Integer.
func (s *String) ReadOptionalASN1Integer(out interface{}, tag Tag, defaultValue interface{}) bool {
	var present bool
	var i String
	if !s.ReadOptionalASN1(&i, &present, tag) {
		return false
	}
	if !present {
		switch out.(type) {
		case *int, *int8, *int16, *int32, *int64,
			*uint, *uint8, *uint16, *uint32, *uint64, *[]byte:
			reflect.ValueOf(out).Elem().Set(reflect.ValueOf(defaultValue))
		case *big.Int:
			if defaultValue, ok := defaultValue.(*big.Int); ok {
				out.(*big.Int).Set(defaultValue)
			} else {
				panic("out points to big.Int, but defaultValue does not")
			}
		default:
			panic("invalid integer type")
		}
		return true
	}
	if !i.ReadASN1Integer(out) || !i.Empty() {
		return false
	}
	return true
}

// ReadOptionalASN1OctetString attempts to read an optional ASN.1 OCTET STRING
// explicitly tagged with tag into out and advances. If no element with a
// matching tag is present, it sets "out" to nil instead. It reports
// whether the read was successful.
func (s *String) ReadOptionalASN1OctetString(out *[]byte, outPresent *bool, tag Tag) bool {
	var present bool
	var child String
	if !s.ReadOptionalASN1(&child, &present, tag) {
		return false
	}
	if outPresent != nil {
		*outPresent = present
	}
	if present {
		var oct String
		if !child.ReadASN1(&oct, OCTET_STRING) || !child.Empty() {
			return false
		}
		*out = oct
	} else {
		*out = nil
	}
	return true
}

// ReadOptionalASN1Boolean attempts to read an optional ASN.1 BOOLEAN
// explicitly tagged with tag into out and advances. If no element with a
// matching tag is present, it sets "out" to defaultValue instead. It reports
// whether the read was successful.
func (s *String) ReadOptionalASN1Boolean(out *bool, tag Tag, defaultValue bool) bool {
	var present bool
	var child String
	if !s.ReadOptionalASN1(&child, &present, tag) {
		return false
	}

	if !present {
		*out = defaultValue
		return true
	}

	return child.ReadASN1Boolean(out)
}

func (s *String) readASN1(out *String, outTag *Tag, skipHeader bool) bool {
	if len(*s) < 2 {
		return false
	}
	tag, lenByte := (*s)[0], (*s)[1]

	if tag&0x1f == 0x1f {
		// ITU-T X.690 section 8.1.2
		//
		// An identifier octet with a tag part of 0x1f indicates a high-tag-number
		// form identifier with two or more octets. We only support tags less than
		// 31 (i.e. low-tag-number form, single octet identifier).
		return false
	}

	if outTag != nil {
		*outTag = Tag(tag)
	}

	// ITU-T X.690 section 8.1.3
	//
	// Bit 8 of the first length byte indicates whether the length is short- or
	// long-form.
	var length, headerLen uint32 // length includes headerLen
	if lenByte&0x80 == 0 {
		// Short-form length (section 8.1.3.4), encoded in bits 1-7.
		length = uint32(lenByte) + 2
		headerLen = 2
	} else {
		// Long-form length (section 8.1.3.5). Bits 1-7 encode the number of octets
		// used to encode the length.
		lenLen := lenByte & 0x7f
		var len32 uint32

		if lenLen == 0 || lenLen > 4 || len(*s) < int(2+lenLen) {
			return false
		}

		lenBytes := String((*s)[2 : 2+lenLen])
		if !lenBytes.readUnsigned(&len32, int(lenLen)) {
			return false
		}

		// ITU-T X.690 section 10.1 (DER length forms) requires encoding the length
		// with the minimum number of octets.
		if len32 < 128 {
			// Length should have used short-form encoding.
			return false
		}
		if len32>>((lenLen-1)*8) == 0 {
			// Leading octet is 0. Length should have been at least one byte shorter.
			return false
		}

		headerLen = 2 + uint32(lenLen)
		if headerLen+len32 < len32 {
			// Overflow.
			return false
		}
		length = headerLen + len32
	}

	if int(length) < 0 || !s.ReadBytes((*[]byte)(out), int(length)) {
		return false
	}
	if skipHeader && !out.Skip(int(headerLen)) {
		panic("cryptobyte: internal error")
	}

	return true
}
