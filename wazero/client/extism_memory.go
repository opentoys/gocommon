package client

import "encoding/binary"

type ExtismPointer uint64

// Allocate allocates `length` uninitialized bytes on the host.
func Allocate(length int) Memory {
	clength := uint64(length)
	offset := ExtismAlloc(clength)

	return NewMemory(offset, clength)
}

// AllocateBytes allocates and saves the `data` into Memory on the host.
func AllocateBytes(data []byte) Memory {
	clength := uint64(len(data))
	offset := ExtismAlloc(clength)

	Store(offset, data)

	return NewMemory(offset, clength)
}

// extismStoreU8 stores the byte `v` at location `offset` in the host memory block.
//
//go:wasmimport extism:host/env store_u8
func extismStoreU8_(ExtismPointer, uint32)
func ExtismStoreU8(offset ExtismPointer, v uint8) {
	extismStoreU8_(offset, uint32(v))
}

// extismLoadU8 returns the byte located at `offset` in the host memory block.
//
//go:wasmimport extism:host/env load_u8
func extismLoadU8_(offset ExtismPointer) uint32
func ExtismLoadU8(offset ExtismPointer) uint8 {
	return uint8(extismLoadU8_(offset))
}

// extismStoreU64 stores the 64-bit unsigned integer value `v` at location `offset` in the host memory block.
// Note that `offset` must lie on an 8-byte boundary.
//
//go:wasmimport extism:host/env store_u64
func ExtismStoreU64(offset ExtismPointer, v uint64)

// extismLoadU64 returns the 64-bit unsigned integer at location `offset` in the host memory block.
// Note that `offset` must lie on an 8-byte boundary.
//
//go:wasmimport extism:host/env load_u64
func ExtismLoadU64(offset ExtismPointer) uint64

//go:wasmimport extism:host/env length_unsafe
func ExtismLengthUnsafe(ExtismPointer) uint64

// extismLength returns the number of bytes associated with the block of host memory
// located at `offset`.
//
//go:wasmimport extism:host/env length
func ExtismLength(offset ExtismPointer) uint64

// extismAlloc allocates `length` bytes of data with host memory for use by the plugin
// and returns its offset within the host memory block.
//
//go:wasmimport extism:host/env alloc
func ExtismAlloc(length uint64) ExtismPointer

// extismFree releases the bytes previously allocated with `extism_alloc` at the given `offset`.
//
//go:wasmimport extism:host/env free
func ExtismFree(offset ExtismPointer)

func Load(offset ExtismPointer, buf []byte) {
	length := len(buf)
	chunkCount := length >> 3

	for chunkIdx := 0; chunkIdx < chunkCount; chunkIdx++ {
		i := chunkIdx << 3
		binary.LittleEndian.PutUint64(buf[i:i+8], ExtismLoadU64(offset+ExtismPointer(i)))
	}

	remainder := length & 7
	remainderOffset := chunkCount << 3
	for index := remainderOffset; index < (remainder + remainderOffset); index++ {
		buf[index] = ExtismLoadU8(offset + ExtismPointer(index))
	}
}

func Store(offset ExtismPointer, buf []byte) {
	length := len(buf)
	chunkCount := length >> 3

	for chunkIdx := 0; chunkIdx < chunkCount; chunkIdx++ {
		i := chunkIdx << 3
		x := binary.LittleEndian.Uint64(buf[i : i+8])
		ExtismStoreU64(offset+ExtismPointer(i), x)
	}

	remainder := length & 7
	remainderOffset := chunkCount << 3
	for index := remainderOffset; index < (remainder + remainderOffset); index++ {
		ExtismStoreU8(offset+ExtismPointer(index), buf[index])
	}
}

func NewMemory(offset ExtismPointer, length uint64) Memory {
	return Memory{
		offset: offset,
		length: length,
	}
}

// Memory represents memory allocated by (and shared with) the host.
type Memory struct {
	offset ExtismPointer
	length uint64
}

// Load copies the host memory block to the provided `buffer` byte slice.
func (m *Memory) Load(buffer []byte) {
	Load(m.offset, buffer)
}

// Store copies the `data` byte slice into host memory.
func (m *Memory) Store(data []byte) {
	Store(m.offset, data)
}

// Free frees the host memory block.
func (m *Memory) Free() {
	ExtismFree(m.offset)

}

// Length returns the number of bytes in the host memory block.
func (m *Memory) Length() uint64 {
	return m.length
}

// Offset returns the offset of the host memory block.
func (m *Memory) Offset() uint64 {
	return uint64(m.offset)
}

// ReadBytes returns the host memory block as a slice of bytes.
func (m *Memory) ReadBytes() []byte {
	buff := make([]byte, m.length)
	m.Load(buff)
	return buff
}
