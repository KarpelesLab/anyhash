package anyhash

// Jenkins one-at-a-time hash.

import "encoding/binary"

func init() {
	registerHash("joaat", func() Hash { return new(joaatDigest) })
}

type joaatDigest struct {
	h   uint32
	len uint64
}

func (d *joaatDigest) Size() int      { return 4 }
func (d *joaatDigest) BlockSize() int { return 1 }

func (d *joaatDigest) Reset() { *d = joaatDigest{} }

func (d *joaatDigest) Clone() Hash {
	c := *d
	return &c
}

func (d *joaatDigest) Write(p []byte) (int, error) {
	h := d.h
	for _, b := range p {
		h += uint32(b)
		h += h << 10
		h ^= h >> 6
	}
	d.h = h
	d.len += uint64(len(p))
	return len(p), nil
}

func (d *joaatDigest) Sum(in []byte) []byte {
	h := d.h
	h += h << 3
	h ^= h >> 11
	h += h << 15
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], h)
	return append(in, buf[:]...)
}
