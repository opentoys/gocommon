// Fork https://github.com/stek29/base100
package base100

// Licensed under UNLICENSE
// See UNLICENSE provided with this file for details
// For more information, please refer to <http://unlicense.org/>

const (
	first  = 0xf0
	second = 0x9f

	shift   = 55
	divisor = 64

	third = 0x8f
	forth = 0x80
)

// Encode tranforms bytes into base100 utf-8 encoded string
func Encode(data []byte) string {
	result := make([]byte, len(data)*4)
	for i, b := range data {
		result[i*4+0] = first
		result[i*4+1] = second
		result[i*4+2] = byte((uint16(b)+shift)/divisor + third)
		result[i*4+3] = (b+shift)%divisor + forth
	}
	return string(result)
}

// InvalidInputError is returned when Decode fails
type InvalidInputError struct {
	message string
}

func (e InvalidInputError) Error() string {
	return e.message
}

// ErrInvalidLength is returned when length of string being decoded is
// not divisible by four
var ErrInvalidLength = InvalidInputError{"len(data) should be divisible by 4"}

// ErrInvalidData is returned if data is not a valid base100 string
var ErrInvalidData = InvalidInputError{"data is invalid"}

// Decode transforms base100 utf-8 encoded string into bytes
func Decode(data string) ([]byte, error) {
	if len(data)%4 != 0 {
		return nil, ErrInvalidLength
	}

	result := make([]byte, len(data)/4)
	for i := 0; i != len(data); i += 4 {
		if data[i+0] != first || data[i+1] != second {
			return nil, ErrInvalidData
		}

		result[i/4] = (data[i+2]-third)*divisor +
			data[i+3] - forth - shift
	}
	return result, nil
}
