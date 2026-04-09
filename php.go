package anyhash

import (
	"encoding"
	"encoding/binary"
	"fmt"
	"hash"
)

// phpWrapHash creates a hashWrapper with PHP marshaling support.
func phpWrapHash(phpAlgo string, fn func() hash.Hash, enc phpCodec) *phpHashWrapper {
	return &phpHashWrapper{
		hashWrapper: hashWrapper{Hash: fn(), make: fn},
		phpAlgo:     phpAlgo,
		codec:       enc,
	}
}

// phpHashWrapper extends hashWrapper with PHP serialization support.
type phpHashWrapper struct {
	hashWrapper
	phpAlgo string
	codec   phpCodec
}

func (w *phpHashWrapper) Clone() Hash {
	inner := w.hashWrapper.Clone().(*hashWrapper)
	return &phpHashWrapper{
		hashWrapper: *inner,
		phpAlgo:     w.phpAlgo,
		codec:       w.codec,
	}
}

func (w *phpHashWrapper) PHPAlgo() string { return w.phpAlgo }

func (w *phpHashWrapper) MarshalPHP() ([]int32, []byte) {
	state, err := w.Hash.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic("anyhash: php marshal: " + err.Error())
	}
	return w.codec.marshal(state)
}

func (w *phpHashWrapper) UnmarshalPHP(ints []int32, buf []byte) error {
	state, err := w.codec.unmarshal(ints, buf)
	if err != nil {
		return err
	}
	return w.Hash.(encoding.BinaryUnmarshaler).UnmarshalBinary(state)
}

// phpCodec defines how to convert between Go's binary marshal format and PHP's int32+buffer format.
type phpCodec struct {
	marshal   func(goState []byte) ([]int32, []byte)
	unmarshal func(ints []int32, buf []byte) (goState []byte, err error)
}

// Helper: reinterpret uint32 as int32 (preserving bits).
func u32toi32(v uint32) int32 { return int32(v) }

// Helper: reinterpret int32 as uint32 (preserving bits).
func i32tou32(v int32) uint32 { return uint32(v) }

// Helper: split uint64 into two int32 (low, high).
func u64toi32pair(v uint64) (int32, int32) {
	return int32(uint32(v)), int32(uint32(v >> 32))
}

// Helper: combine two int32 (low, high) into uint64.
func i32pairtou64(lo, hi int32) uint64 {
	return uint64(uint32(lo)) | (uint64(uint32(hi)) << 32)
}

// --- SHA-256 / SHA-224 PHP codec ---
// Go binary format: magic(4) + h[0..7](32) + buffer(0..64) + padding + len(8)
// PHP format: [h0..h7 as int32, countLo, countHi] + buffer(64)

var sha256Codec = phpCodec{
	marshal: func(goState []byte) ([]int32, []byte) {
		// Skip 4-byte magic, read 8 x uint32 state
		ints := make([]int32, 10)
		for i := 0; i < 8; i++ {
			ints[i] = u32toi32(binary.BigEndian.Uint32(goState[4+i*4:]))
		}
		// Buffer is at offset 36, up to 64 bytes, then len at end
		totalLen := binary.BigEndian.Uint64(goState[len(goState)-8:])
		lo, hi := u64toi32pair(totalLen)
		ints[8] = lo
		ints[9] = hi
		buf := make([]byte, 64)
		copy(buf, goState[36:])
		return ints, buf
	},
	unmarshal: func(ints []int32, buf []byte) ([]byte, error) {
		if len(ints) < 10 {
			return nil, fmt.Errorf("anyhash: sha256 PHP state needs 10 ints, got %d", len(ints))
		}
		magic := []byte("sha\x03") // sha256 magic
		goState := make([]byte, 4+32+64+8)
		copy(goState, magic)
		for i := 0; i < 8; i++ {
			binary.BigEndian.PutUint32(goState[4+i*4:], i32tou32(ints[i]))
		}
		copy(goState[36:], buf)
		totalLen := i32pairtou64(ints[8], ints[9])
		binary.BigEndian.PutUint64(goState[100:], totalLen)
		return goState, nil
	},
}

var sha224Codec = phpCodec{
	marshal:   sha256Codec.marshal,
	unmarshal: func(ints []int32, buf []byte) ([]byte, error) {
		if len(ints) < 10 {
			return nil, fmt.Errorf("anyhash: sha224 PHP state needs 10 ints, got %d", len(ints))
		}
		magic := []byte("sha\x02") // sha224 magic
		goState := make([]byte, 4+32+64+8)
		copy(goState, magic)
		for i := 0; i < 8; i++ {
			binary.BigEndian.PutUint32(goState[4+i*4:], i32tou32(ints[i]))
		}
		copy(goState[36:], buf)
		totalLen := i32pairtou64(ints[8], ints[9])
		binary.BigEndian.PutUint64(goState[100:], totalLen)
		return goState, nil
	},
}

// --- SHA-1 PHP codec ---
// Go binary format: magic(4) + h[0..4](20) + buffer(0..64) + padding + len(8)
// PHP format: [h0..h4 as int32, countLo, countHi] + buffer(64)

var sha1Codec = phpCodec{
	marshal: func(goState []byte) ([]int32, []byte) {
		ints := make([]int32, 7)
		for i := 0; i < 5; i++ {
			ints[i] = u32toi32(binary.BigEndian.Uint32(goState[4+i*4:]))
		}
		totalLen := binary.BigEndian.Uint64(goState[len(goState)-8:])
		lo, hi := u64toi32pair(totalLen)
		ints[5] = lo
		ints[6] = hi
		buf := make([]byte, 64)
		copy(buf, goState[24:])
		return ints, buf
	},
	unmarshal: func(ints []int32, buf []byte) ([]byte, error) {
		if len(ints) < 7 {
			return nil, fmt.Errorf("anyhash: sha1 PHP state needs 7 ints, got %d", len(ints))
		}
		magic := []byte("sha\x01")
		goState := make([]byte, 4+20+64+8)
		copy(goState, magic)
		for i := 0; i < 5; i++ {
			binary.BigEndian.PutUint32(goState[4+i*4:], i32tou32(ints[i]))
		}
		copy(goState[24:], buf)
		totalLen := i32pairtou64(ints[5], ints[6])
		binary.BigEndian.PutUint64(goState[88:], totalLen)
		return goState, nil
	},
}

// --- SHA-512 / SHA-384 / SHA-512/224 / SHA-512/256 PHP codec ---
// Go binary format: magic(4) + h[0..7](64) + buffer(0..128) + padding + len(8)
// PHP format: [h0_hi,h0_lo,...,h7_hi,h7_lo, countLo, countHi, 0, 0] + buffer(128)
// Note: PHP stores each uint64 as (hi,lo) pair, not (lo,hi)!

func makeSHA512Codec(magic string) phpCodec {
	return phpCodec{
		marshal: func(goState []byte) ([]int32, []byte) {
			ints := make([]int32, 20)
			for i := 0; i < 8; i++ {
				v := binary.BigEndian.Uint64(goState[4+i*8:])
				ints[i*2] = int32(uint32(v >> 32)) // hi first (PHP order)
				ints[i*2+1] = int32(uint32(v))     // lo second
			}
			totalLen := binary.BigEndian.Uint64(goState[len(goState)-8:])
			ints[16] = int32(uint32(totalLen))
			ints[17] = int32(uint32(totalLen >> 32))
			ints[18] = 0
			ints[19] = 0
			buf := make([]byte, 128)
			copy(buf, goState[68:])
			return ints, buf
		},
		unmarshal: func(ints []int32, buf []byte) ([]byte, error) {
			if len(ints) < 20 {
				return nil, fmt.Errorf("anyhash: sha512 PHP state needs 20 ints, got %d", len(ints))
			}
			goState := make([]byte, 4+64+128+8)
			copy(goState, magic)
			for i := 0; i < 8; i++ {
				v := uint64(uint32(ints[i*2]))<<32 | uint64(uint32(ints[i*2+1]))
				binary.BigEndian.PutUint64(goState[4+i*8:], v)
			}
			copy(goState[68:], buf)
			totalLen := uint64(uint32(ints[16])) | uint64(uint32(ints[17]))<<32
			binary.BigEndian.PutUint64(goState[196:], totalLen)
			return goState, nil
		},
	}
}

// --- MD5 PHP codec ---
// Go binary format: magic(4) + h[0..3](16) + buffer(0..64) + padding + len(8)
// PHP format: [countLo, countHi, h0..h3] + buffer(64) + [16 zeros]
// Note: MD5 has 23 elements total — the 16 trailing zeros are PHP's "in" block.

var md5Codec = phpCodec{
	marshal: func(goState []byte) ([]int32, []byte) {
		ints := make([]int32, 22)
		// Go MD5 binary: "md5\x01" + h[0..3] LE + buffer + len BE
		totalLen := binary.BigEndian.Uint64(goState[len(goState)-8:])
		// PHP stores count as bits
		bitCount := totalLen * 8
		lo, hi := u64toi32pair(bitCount)
		ints[0] = lo // count lo (in bits)
		ints[1] = hi // count hi
		for i := 0; i < 4; i++ {
			ints[2+i] = u32toi32(binary.LittleEndian.Uint32(goState[4+i*4:]))
		}
		// ints[6..21] are the 16 "in" block words (zeros for us)
		buf := make([]byte, 64)
		copy(buf, goState[20:])
		return ints, buf
	},
	unmarshal: func(ints []int32, buf []byte) ([]byte, error) {
		if len(ints) < 6 {
			return nil, fmt.Errorf("anyhash: md5 PHP state needs at least 6 ints, got %d", len(ints))
		}
		goState := make([]byte, 4+16+64+8)
		copy(goState, "md5\x01")
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint32(goState[4+i*4:], i32tou32(ints[2+i]))
		}
		copy(goState[20:], buf)
		// Convert bit count back to byte count
		bitCount := i32pairtou64(ints[0], ints[1])
		binary.BigEndian.PutUint64(goState[84:], bitCount/8)
		return goState, nil
	},
}

// --- CRC32B / CRC32C PHP codec (stdlib wrapped) ---
// Go crc32 binary format: "crc\x01" + table(4) + crc(4) = 12 bytes
// PHP format: [int32(state)] — the raw state before complement

func makeCRC32Codec(phpAlgo string, fn func() hash.Hash) phpCodec {
	// Pre-compute the table checksum by marshaling a fresh hash
	fresh := fn()
	initState, _ := fresh.(encoding.BinaryMarshaler).MarshalBinary()
	tableSum := binary.BigEndian.Uint32(initState[4:8])

	return phpCodec{
		marshal: func(goState []byte) ([]int32, []byte) {
			state := binary.BigEndian.Uint32(goState[8:])
			return []int32{u32toi32(state)}, nil
		},
		unmarshal: func(ints []int32, buf []byte) ([]byte, error) {
			if len(ints) < 1 {
				return nil, fmt.Errorf("anyhash: crc32 PHP state needs 1 int, got %d", len(ints))
			}
			goState := make([]byte, 12)
			copy(goState, "crc\x01")
			binary.BigEndian.PutUint32(goState[4:], tableSum)
			binary.BigEndian.PutUint32(goState[8:], i32tou32(ints[0]))
			return goState, nil
		},
	}
}

// --- Adler32 PHP codec (stdlib wrapped) ---
// Go adler32 binary: "adl\x01" + state(4) = 8 bytes
// PHP format: [int32(state)]

var adler32Codec = phpCodec{
	marshal: func(goState []byte) ([]int32, []byte) {
		state := binary.BigEndian.Uint32(goState[4:])
		return []int32{u32toi32(state)}, nil
	},
	unmarshal: func(ints []int32, buf []byte) ([]byte, error) {
		if len(ints) < 1 {
			return nil, fmt.Errorf("anyhash: adler32 PHP state needs 1 int, got %d", len(ints))
		}
		goState := make([]byte, 8)
		copy(goState, "adl\x01")
		binary.BigEndian.PutUint32(goState[4:], i32tou32(ints[0]))
		return goState, nil
	},
}

// --- FNV32 / FNV32a PHP codec ---
// Go fnv32 binary: "fnv\x01" / "fnv\x02" + state(4) = 8 bytes
// PHP format: [int32(state)]

func makeFNV32Codec(magic string) phpCodec {
	return phpCodec{
		marshal: func(goState []byte) ([]int32, []byte) {
			state := binary.BigEndian.Uint32(goState[4:])
			return []int32{u32toi32(state)}, nil
		},
		unmarshal: func(ints []int32, buf []byte) ([]byte, error) {
			if len(ints) < 1 {
				return nil, fmt.Errorf("anyhash: fnv32 PHP state needs 1 int, got %d", len(ints))
			}
			goState := make([]byte, 8)
			copy(goState, magic)
			binary.BigEndian.PutUint32(goState[4:], i32tou32(ints[0]))
			return goState, nil
		},
	}
}

// --- FNV64 / FNV64a PHP codec ---
// Go fnv64 binary: "fnv\x03" / "fnv\x04" + state(8) = 12 bytes
// PHP format: [lo_int32, hi_int32]

func makeFNV64Codec(magic string) phpCodec {
	return phpCodec{
		marshal: func(goState []byte) ([]int32, []byte) {
			state := binary.BigEndian.Uint64(goState[4:])
			lo, hi := u64toi32pair(state)
			return []int32{lo, hi}, nil
		},
		unmarshal: func(ints []int32, buf []byte) ([]byte, error) {
			if len(ints) < 2 {
				return nil, fmt.Errorf("anyhash: fnv64 PHP state needs 2 ints, got %d", len(ints))
			}
			goState := make([]byte, 12)
			copy(goState, magic)
			binary.BigEndian.PutUint64(goState[4:], i32pairtou64(ints[0], ints[1]))
			return goState, nil
		},
	}
}

