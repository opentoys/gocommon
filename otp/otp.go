package otp

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
)

var (
	ErrNotSecret        error = errors.New("no secret key provided")
	ErrBadSecret        error = errors.New("bad secret key")
	ErrInvalidAlgorithm error = errors.New("invalid algorithm. Please use any one of SHA1/SHA256/SHA512")
	ErrUnableCompute    error = errors.New("unable to compute HMAC")
)

type OTP interface {
	Generate() (string, error)
	URL() string
	Validate(token string) (ok bool, e error)
}

func generateOTP(key string, cnt int64, digits int, algo string, hasher func(k, b []byte) ([]byte, error)) (token string, e error) {
	var counterbytes = make([]byte, 8)
	binary.BigEndian.PutUint64(counterbytes, uint64(cnt)) // convert counter to byte array
	secretKey, e := base32.StdEncoding.DecodeString(key)  // parse key
	if e != nil {
		e = ErrBadSecret
		return
	}

	hash, e := hasher(secretKey, counterbytes)
	if e != nil {
		e = ErrUnableCompute
		return
	}
	offset := hash[len(hash)-1] & 0xF
	hash = hash[offset : offset+4]

	hash[0] = hash[0] & 0x7F
	decimal := binary.BigEndian.Uint32(hash)
	otp := decimal % uint32(math.Pow10(digits))
	token = strconv.Itoa(int(otp))
	for len(token) != digits {
		token = "0" + token
	}
	return
}
