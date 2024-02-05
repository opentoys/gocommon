/*
Package bcd provides functions to encode byte arrays
to BCD (Binary-Coded Decimal) encoding and back.
*/
package bcd // Fork https://github.com/yerden/go-util/bcd

import (
	"bytes"
	"fmt"
	"io"
)

// BCD is the configuration for Binary-Coded Decimal encoding.
type BCD struct {
	// Map of symbols to encode and decode routines.
	// Example:
	//    key 'a' -> value 0x9
	Map map[byte]byte

	// If true nibbles (4-bit part of a byte) will
	// be swapped, meaning bits 0123 will encode
	// first digit and bits 4567 will encode the
	// second.
	SwapNibbles bool

	// Filler nibble is used if the input has odd
	// number of bytes. Then the output's final nibble
	// will contain the specified nibble.
	Filler byte
}

var (
	// Standard 8-4-2-1 decimal-only encoding.
	Standard = &BCD{
		Map: map[byte]byte{
			'0': 0x0, '1': 0x1, '2': 0x2, '3': 0x3,
			'4': 0x4, '5': 0x5, '6': 0x6, '7': 0x7,
			'8': 0x8, '9': 0x9,
		},
		SwapNibbles: false,
		Filler:      0xf}

	// Excess-3 or Stibitz encoding.
	Excess3 = &BCD{
		Map: map[byte]byte{
			'0': 0x3, '1': 0x4, '2': 0x5, '3': 0x6,
			'4': 0x7, '5': 0x8, '6': 0x9, '7': 0xa,
			'8': 0xb, '9': 0xc,
		},
		SwapNibbles: false,
		Filler:      0x0}

	// TBCD (Telephony BCD) as in 3GPP TS 29.002.
	Telephony = &BCD{
		Map: map[byte]byte{
			'0': 0x0, '1': 0x1, '2': 0x2, '3': 0x3,
			'4': 0x4, '5': 0x5, '6': 0x6, '7': 0x7,
			'8': 0x8, '9': 0x9, '*': 0xa, '#': 0xb,
			'a': 0xc, 'b': 0xd, 'c': 0xe,
		},
		SwapNibbles: true,
		Filler:      0xf}

	// Aiken or 2421 code
	Aiken = &BCD{
		Map: map[byte]byte{
			'0': 0x0, '1': 0x1, '2': 0x2, '3': 0x3,
			'4': 0x4, '5': 0xb, '6': 0xc, '7': 0xd,
			'8': 0xe, '9': 0xf,
		},
		SwapNibbles: false,
		Filler:      0x5}
)

var StdEncoding = NewCodec(Standard)
var Excess3Encoding = NewCodec(Excess3)
var TelephonyEncoding = NewCodec(Telephony)
var AikenEncoding = NewCodec(Aiken)

// Error values returned by API.
var (
	// ErrBadInput returned if input data cannot be encoded.
	ErrBadInput = fmt.Errorf("non-encodable data")
	// ErrBadBCD returned if input data cannot be decoded.
	ErrBadBCD = fmt.Errorf("bad BCD data")
)

type word [2]byte
type dword [4]byte

// Decoder is used to decode BCD converted bytes into decimal string.
//
// Decoder may be copied with no side effects.
type Decoder struct {
	// if the input contains filler nibble in the middle, default
	// behaviour is to treat this as an error. You can tell decoder to
	// resume decoding quietly in that case by setting this.
	IgnoreFiller bool

	// two nibbles (1 byte) to 2 symbols mapping; example: 0x45 ->
	// '45' or '54' depending on nibble swapping additional 2 bytes of
	// dword should be 0, otherwise given byte is unacceptable
	hashWord [0x100]dword

	// one finishing byte with filler nibble to 1 symbol mapping;
	// example: 0x4f -> '4' (filler=0xf, swap=false)
	// additional byte of word should 0, otherise given nibble is
	// unacceptable
	hashByte [0x100]word
}

func newHashDecWord(config *BCD) (res [0x100]dword) {
	var w dword
	var b byte
	for i := range res {
		// invalidating all bytes by default
		res[i] = dword{0xff, 0xff, 0xff, 0xff}
	}

	for c1, nib1 := range config.Map {
		for c2, nib2 := range config.Map {
			b = (nib1 << 4) + nib2&0xf
			if config.SwapNibbles {
				w = dword{c2, c1, 0, 0}
			} else {
				w = dword{c1, c2, 0, 0}
			}
			res[b] = w
		}
	}
	return
}

func newHashDecByte(config *BCD) (res [0x100]word) {
	var b byte
	for i := range res {
		// invalidating all nibbles by default
		res[i] = word{0xff, 0xff}
	}
	for c, nib := range config.Map {
		if config.SwapNibbles {
			b = (config.Filler << 4) + nib&0xf
		} else {
			b = (nib << 4) + config.Filler&0xf
		}
		res[b] = word{c, 0}
	}
	return
}

func (dec *Decoder) unpack(w []byte, b byte) (n int, end bool, err error) {
	if dw := dec.hashWord[b]; dw[2] == 0 {
		return copy(w, dw[:2]), false, nil
	}
	if dw := dec.hashByte[b]; dw[1] == 0 {
		return copy(w, dw[:1]), true, nil
	}
	return 0, false, ErrBadBCD
}

// NewDecoder creates new Decoder from BCD configuration. If the
// configuration is invalid NewDecoder will panic.
func NewDecoder(config *BCD) *Decoder {
	if !checkBCD(config) {
		panic("BCD table is incorrect")
	}

	return &Decoder{
		hashWord: newHashDecWord(config),
		hashByte: newHashDecByte(config)}
}

// DecodedLen tells how much space is needed to store decoded string.
// Please note that it returns the max amount of possibly needed space
// because last octet may contain only one encoded digit. In that
// case the decoded length will be less by 1. For example, 4 octets
// may encode 7 or 8 digits.  Please examine the result of Decode to
// obtain the real value.
func DecodedLen(x int) int {
	return 2 * x
}

// Decode parses BCD encoded bytes from src and tries to decode them
// to dst. Number of decoded bytes and possible error is returned.
func (dec *Decoder) Decode(src []byte) (dst []byte, e error) {
	if len(src) == 0 {
		return src, nil
	}
	dst = make([]byte, DecodedLen(len(src)))
	var n int
	for _, c := range src[:len(src)-1] {
		wid, end, err := dec.unpack(dst[n:], c)
		switch {
		case err != nil: // invalid input
			e = err
			return
		case wid == 0: // no place in dst
			return
		case end && !dec.IgnoreFiller: // unexpected filler
			e = ErrBadBCD
			return
		}
		n += wid
	}

	c := src[len(src)-1]
	wid, _, err := dec.unpack(dst[n:], c)
	switch {
	case err != nil: // invalid input
		e = err
		return
	case wid == 0: // no place in dst
		return
	}
	n += wid
	return
}

// Encoder is used to encode decimal string into BCD bytes.
//
// Encoder may be copied with no side effects.
type Encoder struct {
	// symbol to nibble mapping; example:
	// '*' -> 0xA
	// the value > 0xf means no mapping, i.e. invalid symbol
	hash [0x100]byte

	// nibble used to fill if the number of bytes is odd
	filler byte

	// if true the 0x45 translates to '54' and vice versa
	swap bool
}

func checkBCD(config *BCD) bool {
	nibbles := make(map[byte]bool)
	// check all nibbles
	for _, nib := range config.Map {
		if _, ok := nibbles[nib]; ok || nib > 0xf {
			// already in map or not a nibble
			return false
		}
		nibbles[nib] = true
	}
	return config.Filler <= 0xf
}

func newHashEnc(config *BCD) (res [0x100]byte) {
	for i := 0; i < 0x100; i++ {
		c, ok := config.Map[byte(i)]
		if !ok {
			// no matching symbol
			c = 0xff
		}
		res[i] = c
	}
	return
}

// NewEncoder creates new Encoder from BCD configuration.  If the
// configuration is invalid NewEncoder will panic.
func NewEncoder(config *BCD) *Encoder {
	if !checkBCD(config) {
		panic("BCD table is incorrect")
	}
	return &Encoder{
		hash:   newHashEnc(config),
		filler: config.Filler,
		swap:   config.SwapNibbles}
}

func (enc *Encoder) packNibs(nib1, nib2 byte) byte {
	if enc.swap {
		return (nib2 << 4) + nib1&0xf
	} else {
		return (nib1 << 4) + nib2&0xf
	}
}

func (enc *Encoder) pack(w []byte) (n int, b byte, err error) {
	var nib1, nib2 byte
	switch len(w) {
	case 0:
		n = 0
		return
	case 1:
		n = 1
		if nib1, nib2 = enc.hash[w[0]], enc.filler; nib1 > 0xf {
			err = ErrBadInput
		}
	default:
		n = 2
		if nib1, nib2 = enc.hash[w[0]], enc.hash[w[1]]; nib1 > 0xf || nib2 > 0xf {
			err = ErrBadInput
		}
	}
	return n, enc.packNibs(nib1, nib2), err
}

// EncodedLen returns amount of space needed to store bytes after
// encoding data of length x.
func EncodedLen(x int) int {
	return (x + 1) / 2
}

// Encode get input bytes from src and encodes them into BCD data.
// Number of encoded bytes and possible error is returned.
func (enc *Encoder) Encode(src []byte) (dst []byte, e error) {
	var b byte
	var wid, n int
	dst = make([]byte, EncodedLen(len(src)))

	for n < len(dst) {
		wid, b, e = enc.pack(src)
		switch {
		case e != nil:
			return
		case wid == 0:
			return
		}
		dst[n] = b
		n++
		src = src[wid:]
	}
	return
}

// func (enc *Encoder) Encode

// Reader reads encoded BCD data from underlying io.Reader and decodes
// them. Please pay attention that due to ambiguity of encoding
// process (encoded octet may indicate the end of data by using the
// filler nibble) the last input octet is not decoded until the next
// input octet is observed or until underlying io.Reader returns
// error.
type Reader struct {
	*Decoder
	src io.Reader
	err error
	buf bytes.Buffer
	out []byte
}

// NewReader creates new Reader with underlying io.Reader.
func (dec *Decoder) NewReader(rd io.Reader) *Reader {
	return &Reader{dec, rd, nil, bytes.Buffer{}, []byte{}}
}

// Read implements io.Reader interface.
func (r *Reader) Read(p []byte) (n int, err error) {
	buf := &r.buf

	// return previously decoded data first
	backlog := copy(p[n:], r.out)
	r.out = r.out[backlog:]
	n += backlog
	if len(p) == n {
		return
	}

	if x := EncodedLen(len(p)); r.err == nil {
		// refill on data
		_, r.err = io.CopyN(buf, r.src, int64(x+1))
	}

	if r.err != nil && buf.Len() == 0 {
		// underlying Reader gives no data,
		// buffer is also empty, we're done
		return n, r.err
	}

	// decoding buffer
	w := make([]byte, 2)

	// no error yet, we have some data to decode;
	// decoding until the only byte is left in buffer
	for buf.Len() > 1 && n < len(p) {
		b, _ := buf.ReadByte()
		wid, end, err := r.unpack(w, b)
		if err != nil {
			return n, err
		}

		if end && !r.IgnoreFiller {
			err = ErrBadBCD
		}

		// fmt.Printf("copying '%c' '%c' - %d bytes\n", w[0], w[1], wid)
		cp := copy(p[n:], w[:wid])
		r.out = append(r.out, w[cp:wid]...)
		n += cp

		if err != nil {
			return n, err
		}
	}

	// last breath
	if buf.Len() == 1 && r.err != nil {
		b, _ := buf.ReadByte()
		wid, _, err := r.unpack(w, b)
		if err != nil {
			return n, err
		}

		// fmt.Printf("copying '%c' '%c' - %d bytes\n", w[0], w[1], wid)
		cp := copy(p[n:], w[:wid])
		r.out = append(r.out, w[cp:wid]...)
		n += cp
	}

	return
}

// Writer encodes input data and writes it to underlying io.Writer.
// Please pay attention that due to ambiguity of encoding process
// (encoded octet may indicate the end of data by using the filler
// nibble) Writer will not write odd remainder of the encoded input
// data if any until the next octet is observed.
type Writer struct {
	*Encoder
	dst  io.Writer
	err  error
	word []byte
}

// NewWriter creates new Writer with underlying io.Writer.
func (enc *Encoder) NewWriter(wr io.Writer) *Writer {
	return &Writer{enc, wr, nil, make([]byte, 0, 2)}
}

// Write implements io.Writer interface.
func (w *Writer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	// if we have remaining byte from previous run
	// join it with one of new input and encode
	if len(w.word) == 1 {
		x := append(w.word, p[0])
		_, b, err := w.pack(x)
		if err != nil {
			return 0, err
		}
		if _, err = w.dst.Write([]byte{b}); err != nil {
			return 0, err
		}
		w.word = w.word[:0]
		n += 1
	}

	// encode even number of bytes
	for len(p[n:]) >= 2 {
		_, b, err := w.pack(p[n : n+2])
		if err != nil {
			return n, err
		}
		if _, err = w.dst.Write([]byte{b}); err != nil {
			return n, err
		}
		n += 2
	}

	// save remainder
	if len(p[n:]) > 0 { // == 1
		w.word = append(w.word, p[n])
		n += 1
	}

	return
}

// Encodes all backlogged data to underlying Writer.  If number of
// bytes is odd, the padding fillers will be applied. Because of this
// the main usage of Flush is right before stopping Write()-ing data
// to properly finalize the encoding process.
func (w *Writer) Flush() error {
	if len(w.word) == 0 {
		return nil
	}
	n, b, err := w.pack(w.word)
	w.word = w.word[:0]
	if err != nil {
		// panic("hell")
		return err
	}
	if n == 0 {
		return nil
	}
	_, err = w.dst.Write([]byte{b})
	return err
}

// Buffered returns the number of bytes stored in backlog awaiting for
// its pair.
func (w *Writer) Buffered() int {
	return len(w.word)
}

// Codec encapsulates both Encoder and Decoder.
type Codec struct {
	Encoder
	Decoder
}

// NewCodec returns new copy of Codec. See NewEncoder and NewDecoder
// on behaviour specifics.
func NewCodec(config *BCD) *Codec {
	return &Codec{*NewEncoder(config), *NewDecoder(config)}
}
