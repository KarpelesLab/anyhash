package anyhash

// MD4 implementation per RFC 1320.

import (
	"encoding/binary"
	"math/bits"
)

const md4BlockSize = 64
const md4Size = 16

type md4digest struct {
	s   [4]uint32  // hash state (a, b, c, d)
	buf [64]byte   // partial block buffer
	len uint64     // total bytes written
}

func newMD4() *md4digest {
	d := &md4digest{}
	d.Reset()
	return d
}

func (d *md4digest) Size() int      { return md4Size }
func (d *md4digest) BlockSize() int { return md4BlockSize }

func (d *md4digest) Reset() {
	d.s[0] = 0x67452301
	d.s[1] = 0xefcdab89
	d.s[2] = 0x98badcfe
	d.s[3] = 0x10325476
	d.len = 0
}

func (d *md4digest) Clone() Hash {
	c := *d
	return &c
}

func (d *md4digest) Write(p []byte) (int, error) {
	n := len(p)
	d.len += uint64(n)

	bufLen := int((d.len - uint64(n)) % md4BlockSize)

	if bufLen > 0 {
		fill := copy(d.buf[bufLen:], p)
		bufLen += fill
		p = p[fill:]
		if bufLen == md4BlockSize {
			md4Block(&d.s, d.buf[:])
		}
	}

	for len(p) >= md4BlockSize {
		md4Block(&d.s, p[:md4BlockSize])
		p = p[md4BlockSize:]
	}

	if len(p) > 0 {
		copy(d.buf[:], p)
	}

	return n, nil
}

func (d *md4digest) Sum(in []byte) []byte {
	// Copy so caller can continue writing.
	d0 := *d

	// Padding.
	var tmp [72]byte // enough for padding + length
	tmp[0] = 0x80
	bufLen := d0.len % md4BlockSize
	var padLen uint64
	if bufLen < 56 {
		padLen = 56 - bufLen
	} else {
		padLen = 64 + 56 - bufLen
	}
	binary.LittleEndian.PutUint64(tmp[padLen:], d0.len*8)
	d0.Write(tmp[:padLen+8])

	var digest [md4Size]byte
	binary.LittleEndian.PutUint32(digest[0:], d0.s[0])
	binary.LittleEndian.PutUint32(digest[4:], d0.s[1])
	binary.LittleEndian.PutUint32(digest[8:], d0.s[2])
	binary.LittleEndian.PutUint32(digest[12:], d0.s[3])
	return append(in, digest[:]...)
}

func md4Block(s *[4]uint32, block []byte) {
	var x [16]uint32
	for i := 0; i < 16; i++ {
		x[i] = binary.LittleEndian.Uint32(block[i*4:])
	}

	a, b, c, d := s[0], s[1], s[2], s[3]

	// Round 1
	for _, i := range [...]int{0, 4, 8, 12} {
		a = bits.RotateLeft32(a+((b&c)|(^b&d))+x[i], 3)
		d = bits.RotateLeft32(d+((a&b)|(^a&c))+x[i+1], 7)
		c = bits.RotateLeft32(c+((d&a)|(^d&b))+x[i+2], 11)
		b = bits.RotateLeft32(b+((c&d)|(^c&a))+x[i+3], 19)
	}

	// Round 2
	for _, i := range [...]int{0, 1, 2, 3} {
		a = bits.RotateLeft32(a+((b&c)|(b&d)|(c&d))+x[i]+0x5a827999, 3)
		d = bits.RotateLeft32(d+((a&b)|(a&c)|(b&c))+x[i+4]+0x5a827999, 5)
		c = bits.RotateLeft32(c+((d&a)|(d&b)|(a&b))+x[i+8]+0x5a827999, 9)
		b = bits.RotateLeft32(b+((c&d)|(c&a)|(d&a))+x[i+12]+0x5a827999, 13)
	}

	// Round 3
	for _, i := range [...]int{0, 2, 1, 3} {
		a = bits.RotateLeft32(a+(b^c^d)+x[i]+0x6ed9eba1, 3)
		d = bits.RotateLeft32(d+(a^b^c)+x[i+8]+0x6ed9eba1, 9)
		c = bits.RotateLeft32(c+(d^a^b)+x[i+4]+0x6ed9eba1, 11)
		b = bits.RotateLeft32(b+(c^d^a)+x[i+12]+0x6ed9eba1, 15)
	}

	s[0] += a
	s[1] += b
	s[2] += c
	s[3] += d
}
