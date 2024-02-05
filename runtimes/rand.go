package runtimes

import (
	_ "unsafe"
)

//go:linkname fastrand runtime.fastrand
//go:nosplit
func fastrand() uint32

func Rand() uint32 {
	return fastrand()
}

func RandN(max uint64) uint64 {
	return uint64(fastrand()) * max >> 32
}

func RandIntN(max int32) int32 {
	return int32(fastrand())
}

func RandFloat64N(max float64) float64 {
	return float64(fastrand()) / (1 << 63)
}

func RandFloat32N(max float32) float32 {
	return float32(fastrand()) / (1 << 31)
}
