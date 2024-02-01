package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"
	"time"
)

type TOption func(*totp)

func TOTPWithDigits(n int) TOption {
	return func(t *totp) {
		t.digits = n
	}
}

func TOTPWithDelay(n int) TOption {
	return func(t *totp) {
		t.delay = n
	}
}

func TOTPWithAlgorithm(algo string) TOption {
	return func(t *totp) {
		t.algorithm = algo
	}
}

func TOTPWithUinx(ts int64) TOption {
	return func(t *totp) {
		t.unixTime = ts
	}
}

func TOTPWithPeriod(ts int64) TOption {
	return func(t *totp) {
		t.period = ts
	}
}

// TOTP represents Time-based OTP.
// See https://datatracker.ietf.org/doc/html/rfc6238
type totp struct {
	secret    string                                      // Secret key (required)
	digits    int                                         // OTP digit count (default: 6)
	algorithm string                                      // OTP Algorithm ("SHA1" or "SHA256" or "SHA512") (default: SHA1)
	period    int64                                       // Period for which OTP is valid (seconds) (default: 30)
	unixTime  int64                                       // (Optional) Unix Timestamp (default: Current unix timestamp)
	delay     int                                         // support before and after step, default: 3
	hasher    func(key, buf []byte) (dst []byte, e error) // custom hamc hash
}

func NewTOTP(key string, opts ...TOption) *totp {
	var s = &totp{secret: key}
	for k := range opts {
		opts[k](s)
	}
	if s.algorithm == "" {
		s.algorithm = "SHA1"
	}
	return s
}

// URL https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
// otpauth://totp/{label}?secret=%s&issuer={isuser}&algorithm=%s&digits=%d&period=%d
func (s *totp) URL(label, issuer string) string {
	return fmt.Sprintf(`otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d`, label, s.secret, issuer, s.algorithm, s.digits, s.period)
}

func (s *totp) Generate() (string, error) {
	if e := s._default(); e != nil {
		return "", e
	}
	var now = s.unixTime
	if now == 0 {
		now = time.Now().Unix()
	}
	return generateOTP(s.secret, now/s.period, s.digits, s.algorithm, s.hasher)
}

func (s *totp) _default() (e error) {
	if s.secret == "" {
		return ErrNotSecret
	}

	if s.digits == 0 {
		s.digits = 6
	}

	if s.algorithm == "" {
		s.algorithm = "SHA1"
	}

	if s.period == 0 {
		s.period = 30
	}

	if s.delay == 0 {
		s.delay = 3
	}

	if s.hasher == nil {
		s.hasher = func(key, buf []byte) (dst []byte, e error) {
			var hash hash.Hash
			switch strings.ToUpper(s.algorithm) {
			case "SHA1":
				hash = hmac.New(sha1.New, key)
			case "SHA256":
				hash = hmac.New(sha256.New, key)
			case "SHA512":
				hash = hmac.New(sha512.New, key)
			default:
				return nil, ErrInvalidAlgorithm
			}
			_, e = hash.Write(buf)
			if e != nil {
				return
			}
			dst = hash.Sum(nil)
			return
		}
	}

	return
}

func (s *totp) Validate(token string) (ok bool, e error) {
	if e = s._default(); e != nil {
		return
	}
	var now = s.unixTime
	if now == 0 {
		now = time.Now().Unix()
	}

	var pad int64
	var expected string
	// Now go through all the possible valid tokens
	for step := 0; step <= s.delay; step++ {
		pad = s.period * int64(step)

		expected, e = generateOTP(s.secret, (now-pad)/s.period, s.digits, s.algorithm, s.hasher)
		if e != nil {
			return
		}
		if expected == token {
			ok = true
			return
		}

		expected, e = generateOTP(s.secret, (now+pad)/s.period, s.digits, s.algorithm, s.hasher)
		if e != nil {
			return
		}
		if expected == token {
			ok = true
			return
		}
	}
	return
}
