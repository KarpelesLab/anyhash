package anyhash

import (
	"encoding/binary"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/fnv"
)

func init() {
	registerHash("adler32", func() Hash { return wrapHash(func() hash.Hash { return adler32.New() }) })
	registerHash("crc32", func() Hash { return newCRC32MSB() })
	registerHash("crc32b", func() Hash { return wrapHash(func() hash.Hash { return crc32.New(crc32.IEEETable) }) })
	registerHash("crc32c", func() Hash { return wrapHash(func() hash.Hash { return crc32.New(crc32.MakeTable(crc32.Castagnoli)) }) })
	registerHash("fnv132", func() Hash { return wrapHash(func() hash.Hash { return fnv.New32() }) })
	registerHash("fnv1a32", func() Hash { return wrapHash(func() hash.Hash { return fnv.New32a() }) })
	registerHash("fnv164", func() Hash { return wrapHash(func() hash.Hash { return fnv.New64() }) })
	registerHash("fnv1a64", func() Hash { return wrapHash(func() hash.Hash { return fnv.New64a() }) })
}

// crc32MSB implements CRC-32 with MSB-first (unreflected) polynomial 0x04C11DB7.
// This matches PHP's hash("crc32", ...) which is different from the more common
// CRC-32B (reflected/LSB-first) used by crc32b.
type crc32MSB struct {
	state uint32
}

// Pre-computed table for MSB-first CRC-32 with polynomial 0x04C11DB7.
var crc32MSBTable [256]uint32

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
}

func newCRC32MSB() *crc32MSB {
	return &crc32MSB{state: 0xFFFFFFFF}
}

func (c *crc32MSB) Size() int      { return 4 }
func (c *crc32MSB) BlockSize() int { return 1 }
func (c *crc32MSB) Reset()         { c.state = 0xFFFFFFFF }
func (c *crc32MSB) Clone() Hash    { d := *c; return &d }

func (c *crc32MSB) Write(p []byte) (int, error) {
	s := c.state
	for _, b := range p {
		s = (s << 8) ^ crc32MSBTable[(s>>24)^uint32(b)]
	}
	c.state = s
	return len(p), nil
}

func (c *crc32MSB) Sum(in []byte) []byte {
	s := ^c.state
	var buf [4]byte
	// PHP outputs crc32 in little-endian byte order
	binary.LittleEndian.PutUint32(buf[:], s)
	return append(in, buf[:]...)
}
