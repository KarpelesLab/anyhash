package anyhash

import (
	"encoding/binary"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/fnv"
)

func init() {
	registerHash("adler32", func() Hash { return phpWrapHash("adler32", func() hash.Hash { return adler32.New() }, adler32Codec) })
	registerHash("crc32", func() Hash { return newCRC32MSB() })
	crc32bFn := func() hash.Hash { return crc32.New(crc32.IEEETable) }
	crc32cFn := func() hash.Hash { return crc32.New(crc32.MakeTable(crc32.Castagnoli)) }
	registerHash("crc32b", func() Hash { return phpWrapHash("crc32b", crc32bFn, makeCRC32Codec("crc32b", crc32bFn)) })
	registerHash("crc32c", func() Hash { return phpWrapHash("crc32c", crc32cFn, makeCRC32Codec("crc32c", crc32cFn)) })
	registerHash("fnv132", func() Hash { return phpWrapHash("fnv132", func() hash.Hash { return fnv.New32() }, makeFNV32Codec("fnv\x01")) })
	registerHash("fnv1a32", func() Hash { return phpWrapHash("fnv1a32", func() hash.Hash { return fnv.New32a() }, makeFNV32Codec("fnv\x02")) })
	registerHash("fnv164", func() Hash { return phpWrapHash("fnv164", func() hash.Hash { return fnv.New64() }, makeFNV64Codec("fnv\x03")) })
	registerHash("fnv1a64", func() Hash { return phpWrapHash("fnv1a64", func() hash.Hash { return fnv.New64a() }, makeFNV64Codec("fnv\x04")) })
}

// crc32MSB implements CRC-32 with MSB-first (unreflected) polynomial 0x04C11DB7.
// This matches PHP's hash("crc32", ...) which is different from the more common
// CRC-32B (reflected/LSB-first) used by crc32b.
type crc32MSB struct {
	state uint32
}

// Pre-computed table for MSB-first CRC-32 with polynomial 0x04C11DB7.
var crc32MSBTable [256]uint32

// crc32MSBTable8 is the slicing-by-8 extension of crc32MSBTable.
// T8[0][i] = T[i] (one MSB step with zero state, byte i in top position).
// T8[k][i] = one additional zero-byte MSB step applied to T8[k-1][i].
// The 8-byte update formula (after XOR-ing the first 4 input bytes into the
// high end of the state) is:
//
//	s_new = T8[7][s>>24] ^ T8[6][(s>>16)&0xFF] ^ T8[5][(s>>8)&0xFF] ^ T8[4][s&0xFF] ^
//	        T8[3][p[4]]  ^ T8[2][p[5]]          ^ T8[1][p[6]]        ^ T8[0][p[7]]
var crc32MSBTable8 [8][256]uint32

func init() {
	const poly = 0x04C11DB7
	for i := 0; i < 256; i++ {
		crc := uint32(i) << 24
		for j := 0; j < 8; j++ {
			if crc&0x80000000 != 0 {
				crc = (crc << 1) ^ poly
			} else {
				crc <<= 1
			}
		}
		crc32MSBTable[i] = crc
	}

	// Build slicing-by-8 tables.
	// T8[0] == T (the base table).
	crc32MSBTable8[0] = crc32MSBTable
	// Each subsequent table is one more zero-byte MSB step:
	//   T8[k][i] = (T8[k-1][i] << 8) ^ T[T8[k-1][i] >> 24]
	for k := 1; k < 8; k++ {
		for i := 0; i < 256; i++ {
			v := crc32MSBTable8[k-1][i]
			crc32MSBTable8[k][i] = (v << 8) ^ crc32MSBTable[v>>24]
		}
	}
}

func newCRC32MSB() *crc32MSB {
	return &crc32MSB{state: 0xFFFFFFFF}
}

func (c *crc32MSB) Size() int      { return 4 }
func (c *crc32MSB) BlockSize() int { return 1 }
func (c *crc32MSB) Reset()         { c.state = 0xFFFFFFFF }
func (c *crc32MSB) Clone() Hash    { d := *c; return &d }

func (c *crc32MSB) Write(p []byte) (int, error) {
	n := len(p)
	s := c.state
	// Slicing-by-8: process 8 bytes per iteration.
	// XOR the first 4 input bytes into the high end of the state, then
	// combine 8 table lookups to advance by 8 bytes at once.
	for len(p) >= 8 {
		// Mix the first 4 input bytes into the state (big-endian / MSB-first).
		s ^= uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])
		s = crc32MSBTable8[7][s>>24] ^
			crc32MSBTable8[6][(s>>16)&0xFF] ^
			crc32MSBTable8[5][(s>>8)&0xFF] ^
			crc32MSBTable8[4][s&0xFF] ^
			crc32MSBTable8[3][p[4]] ^
			crc32MSBTable8[2][p[5]] ^
			crc32MSBTable8[1][p[6]] ^
			crc32MSBTable8[0][p[7]]
		p = p[8:]
	}
	// Scalar tail for remaining bytes.
	for _, b := range p {
		s = (s << 8) ^ crc32MSBTable[(s>>24)^uint32(b)]
	}
	c.state = s
	return n, nil
}

func (c *crc32MSB) PHPAlgo() string    { return "crc32" }
func (c *crc32MSB) MarshalPHP() []any  { return []any{int32(c.state)} }
func (c *crc32MSB) UnmarshalPHP(state []any) error {
	if len(state) < 1 {
		return fmt.Errorf("anyhash: crc32 PHP state needs 1 element")
	}
	c.state = uint32(phpInt(state, 0))
	return nil
}

func (c *crc32MSB) Sum(in []byte) []byte {
	s := ^c.state
	var buf [4]byte
	// PHP outputs crc32 in little-endian byte order
	binary.LittleEndian.PutUint32(buf[:], s)
	return append(in, buf[:]...)
}
