package anyhash

// GOST R 34.11-94 hash function with GOST 28147-89 block cipher.

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

var (
	gostTestSboxT      = buildGostSboxTables(&gostTestSbox)
	gostCryptoProSboxT = buildGostSboxTables(&gostCryptoProSbox)
)

func init() {
	registerHash("gost", func() Hash { return newGOST(gostTestSboxT, "gost") })
	registerHash("gostcrypto", func() Hash { return newGOST(gostCryptoProSboxT, "gost-crypto") })
}

// gostSboxTables holds the precomputed 4×256 lookup tables that fold the GOST
// S-box substitution with the 11-bit left rotation into a single uint32
// lookup per input byte.
type gostSboxTables [4][256]uint32

func buildGostSboxTables(s *gostSbox) *gostSboxTables {
	var t gostSboxTables
	for k := 0; k < 4; k++ {
		for b := 0; b < 256; b++ {
			lo := uint32(s[2*k][b&0x0f])
			hi := uint32(s[2*k+1][b>>4])
			v := ((hi << 4) | lo) << (uint(k) * 8)
			t[k][b] = bits.RotateLeft32(v, 11)
		}
	}
	return &t
}

// S-box tables for GOST 28147-89, each row maps 4 bits to 4 bits.
type gostSbox [8][16]byte

var gostTestSbox = gostSbox{
	{4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
	{14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
	{5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
	{7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
	{6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
	{4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
	{13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
	{1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12},
}

var gostCryptoProSbox = gostSbox{
	{10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15},
	{5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8},
	{7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13},
	{4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3},
	{7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5},
	{7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3},
	{13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11},
	{1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12},
}

type gostDigest struct {
	h       [32]byte
	sum     [32]byte
	buf     [32]byte
	bufLen  int
	length  uint64
	sbox    *gostSboxTables
	phpAlgo string
}

func newGOST(sbox *gostSboxTables, phpAlgo string) *gostDigest {
	return &gostDigest{sbox: sbox, phpAlgo: phpAlgo}
}

func (d *gostDigest) Size() int      { return 32 }
func (d *gostDigest) BlockSize() int { return 32 }

func (d *gostDigest) Reset() {
	d.h = [32]byte{}
	d.sum = [32]byte{}
	d.buf = [32]byte{}
	d.bufLen = 0
	d.length = 0
}

func (d *gostDigest) Clone() Hash {
	c := *d
	return &c
}

// PHP format: [h_as_8_uint32_LE, sum_as_8_uint32_LE, bitCountLo, bitCountHi, bufLen] + buffer(32)
// Total: 19 ints + 32-byte buffer.
func (d *gostDigest) PHPAlgo() string { return d.phpAlgo }
func (d *gostDigest) MarshalPHP() []any {
	state := make([]any, 0, 20)
	for i := 0; i < 8; i++ {
		state = append(state, int32(binary.LittleEndian.Uint32(d.h[i*4:])))
	}
	for i := 0; i < 8; i++ {
		state = append(state, int32(binary.LittleEndian.Uint32(d.sum[i*4:])))
	}
	bitCount := d.length * 8
	lo, hi := u64toi32pair(bitCount)
	state = append(state, lo, hi)
	state = append(state, int32(d.bufLen))
	buf := make([]byte, 32)
	copy(buf, d.buf[:d.bufLen])
	state = append(state, buf)
	return state
}
func (d *gostDigest) UnmarshalPHP(state []any) error {
	if len(state) < 20 {
		return fmt.Errorf("anyhash: gost PHP state needs 20 elements, got %d", len(state))
	}
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(d.h[i*4:], uint32(phpInt(state, i)))
	}
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(d.sum[i*4:], uint32(phpInt(state, 8+i)))
	}
	bitCount := i32pairtou64(phpInt(state, 16), phpInt(state, 17))
	d.length = bitCount / 8
	d.bufLen = int(phpInt(state, 18))
	copy(d.buf[:], phpBuf(state, 19))
	return nil
}

func (d *gostDigest) Write(p []byte) (int, error) {
	n := len(p)
	d.length += uint64(n)

	// Fill existing buffer first.
	if d.bufLen > 0 {
		fill := copy(d.buf[d.bufLen:], p)
		d.bufLen += fill
		p = p[fill:]
		if d.bufLen == 32 {
			d.process(d.buf[:])
			d.bufLen = 0
		}
	}

	// Process full blocks.
	for len(p) >= 32 {
		d.process(p[:32])
		p = p[32:]
	}

	// Buffer remainder.
	if len(p) > 0 {
		d.bufLen = copy(d.buf[:], p)
	}

	return n, nil
}

// process compresses one 32-byte block into the running hash state.
func (d *gostDigest) process(block []byte) {
	// Add block to running sum (256-bit addition, little-endian).
	gostAddBlocks(&d.sum, block)
	// Compress.
	gostCompress(&d.h, block, d.sbox)
}

func (d *gostDigest) Sum(in []byte) []byte {
	// Work on a copy so the caller can continue writing.
	d0 := *d

	// Process remaining partial block if any.
	if d0.bufLen > 0 {
		var padded [32]byte
		copy(padded[:], d0.buf[:d0.bufLen])
		gostAddBlocks(&d0.sum, padded[:])
		gostCompress(&d0.h, padded[:], d0.sbox)
	}

	// Compress length (in bits) as 256-bit little-endian.
	var lenBlock [32]byte
	bits := d0.length * 8
	binary.LittleEndian.PutUint64(lenBlock[0:8], bits)
	gostCompress(&d0.h, lenBlock[:], d0.sbox)

	// Compress the running sum.
	gostCompress(&d0.h, d0.sum[:], d0.sbox)

	return append(in, d0.h[:]...)
}

// gostAddBlocks adds a 32-byte block to a 256-bit accumulator (little-endian).
func gostAddBlocks(acc *[32]byte, block []byte) {
	var carry uint32
	for i := 0; i < 32; i++ {
		carry += uint32(acc[i]) + uint32(block[i])
		acc[i] = byte(carry)
		carry >>= 8
	}
}

// gostEncrypt performs GOST 28147-89 encryption of a single 64-bit block
// with a 256-bit key.
// gostRound performs one round of GOST 28147-89 using the folded
// S-box+rotate tables. Each uint32 load already includes the 11-bit left
// rotation, so a simple OR across four byte-indexed lookups replaces eight
// variable-shift 4-bit substitutions followed by a rotate.
func gostRound(n1, n2, key uint32, t *gostSboxTables) (uint32, uint32) {
	tmp := n1 + key
	result := t[0][tmp&0xff] | t[1][(tmp>>8)&0xff] | t[2][(tmp>>16)&0xff] | t[3][(tmp>>24)&0xff]
	return n2 ^ result, n1
}

// gostCompress performs the GOST R 34.11-94 compression function: h = f(h, m).
// All 256-bit values are represented as [4]uint64 to avoid byte-level copies
// and XORs; the key schedule produces [8]uint32 directly for gostEncrypt.
func gostCompress(h *[32]byte, m []byte, sbox *gostSboxTables) {
	u := load64s(h)
	v := [4]uint64{
		binary.LittleEndian.Uint64(m[0:]),
		binary.LittleEndian.Uint64(m[8:]),
		binary.LittleEndian.Uint64(m[16:]),
		binary.LittleEndian.Uint64(m[24:]),
	}

	w := xor64s(u, v)
	keys0 := gostKeySchedule64(w)

	transformA64(&u)
	transformA64(&v)
	transformA64(&v)
	w = xor64s(u, v)
	keys1 := gostKeySchedule64(w)

	transformA64(&u)
	u[0] ^= gostCU[0]
	u[1] ^= gostCU[1]
	u[2] ^= gostCU[2]
	u[3] ^= gostCU[3]
	transformA64(&v)
	transformA64(&v)
	w = xor64s(u, v)
	keys2 := gostKeySchedule64(w)

	transformA64(&u)
	transformA64(&v)
	transformA64(&v)
	w = xor64s(u, v)
	keys3 := gostKeySchedule64(w)

	// Encrypt h using keys — operate on 8-byte blocks.
	var s [32]byte
	copy(s[:], h[:])
	gostEncrypt64((*[8]byte)(s[0:8]), &keys0, sbox)
	gostEncrypt64((*[8]byte)(s[8:16]), &keys1, sbox)
	gostEncrypt64((*[8]byte)(s[16:24]), &keys2, sbox)
	gostEncrypt64((*[8]byte)(s[24:32]), &keys3, sbox)

	gostShuffle64(&s, h, m)
	copy(h[:], s[:])
}

func load64s(p *[32]byte) [4]uint64 {
	return [4]uint64{
		binary.LittleEndian.Uint64(p[0:]),
		binary.LittleEndian.Uint64(p[8:]),
		binary.LittleEndian.Uint64(p[16:]),
		binary.LittleEndian.Uint64(p[24:]),
	}
}

func xor64s(a, b [4]uint64) [4]uint64 {
	return [4]uint64{a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]}
}

// transformA64 is A(x) = x2 || x3 || x4 || (x1 ^ x2) on 4 uint64s.
func transformA64(x *[4]uint64) {
	x0 := x[0]
	x[0] = x[1]
	x[1] = x[2]
	x[2] = x[3]
	x[3] = x0 ^ x[0]
}

// gostCU is gostC preloaded as uint64s.
var gostCU = [4]uint64{
	binary.LittleEndian.Uint64(gostC[0:]),
	binary.LittleEndian.Uint64(gostC[8:]),
	binary.LittleEndian.Uint64(gostC[16:]),
	binary.LittleEndian.Uint64(gostC[24:]),
}

// gostC is the constant used in key generation step 3.
var gostC = [32]byte{
	0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
	0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
	0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff,
	0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff,
}

// gostKeySchedule64 applies the P-permutation (4×8 byte matrix transpose) and
// returns the result as 8 uint32 keys ready for gostEncrypt. The permutation
// maps byte j of the output to byte gostKeyPerm[j] of the input, which
// transposes rows and columns: key_word[c] = w_byte[c] | w_byte[c+8]<<8 |
// w_byte[c+16]<<16 | w_byte[c+24]<<24.
func gostKeySchedule64(w [4]uint64) [8]uint32 {
	var k [8]uint32
	for c := 0; c < 8; c++ {
		k[c] = uint32(byte(w[0]>>uint(c*8))) |
			uint32(byte(w[1]>>uint(c*8)))<<8 |
			uint32(byte(w[2]>>uint(c*8)))<<16 |
			uint32(byte(w[3]>>uint(c*8)))<<24
	}
	return k
}

// gostEncrypt64 is gostEncrypt taking precomputed uint32 keys.
func gostEncrypt64(block *[8]byte, k *[8]uint32, sbox *gostSboxTables) {
	n1 := binary.LittleEndian.Uint32(block[0:4])
	n2 := binary.LittleEndian.Uint32(block[4:8])
	for pass := 0; pass < 3; pass++ {
		n1, n2 = gostRound(n1, n2, k[0], sbox)
		n1, n2 = gostRound(n1, n2, k[1], sbox)
		n1, n2 = gostRound(n1, n2, k[2], sbox)
		n1, n2 = gostRound(n1, n2, k[3], sbox)
		n1, n2 = gostRound(n1, n2, k[4], sbox)
		n1, n2 = gostRound(n1, n2, k[5], sbox)
		n1, n2 = gostRound(n1, n2, k[6], sbox)
		n1, n2 = gostRound(n1, n2, k[7], sbox)
	}
	n1, n2 = gostRound(n1, n2, k[7], sbox)
	n1, n2 = gostRound(n1, n2, k[6], sbox)
	n1, n2 = gostRound(n1, n2, k[5], sbox)
	n1, n2 = gostRound(n1, n2, k[4], sbox)
	n1, n2 = gostRound(n1, n2, k[3], sbox)
	n1, n2 = gostRound(n1, n2, k[2], sbox)
	n1, n2 = gostRound(n1, n2, k[1], sbox)
	n1, n2 = gostRound(n1, n2, k[0], sbox)
	binary.LittleEndian.PutUint32(block[0:4], n2)
	binary.LittleEndian.PutUint32(block[4:8], n1)
}

// gostShuffle64 implements the final step of the compression function
// (s = psi^61(h XOR psi(m XOR psi^12(s)))) on four uint64 registers, folding
// the 74 gostPsi iterations, two 32-byte XORs, and the intermediate loads/stores
// 74 gostPsi iterations, two 32-byte XORs, and the intermediate loads/stores
// into a single load-process-store sequence. Each gostPsi becomes 4 shift+or
// ops over uint64s instead of a 30-byte memmove.
func gostShuffle64(s *[32]byte, h *[32]byte, m []byte) {
	a := binary.LittleEndian.Uint64(s[0:8])
	b := binary.LittleEndian.Uint64(s[8:16])
	c := binary.LittleEndian.Uint64(s[16:24])
	d := binary.LittleEndian.Uint64(s[24:32])

	for i := 0; i < 12; i++ {
		a, b, c, d = gostPsi64(a, b, c, d)
	}

	a ^= binary.LittleEndian.Uint64(m[0:8])
	b ^= binary.LittleEndian.Uint64(m[8:16])
	c ^= binary.LittleEndian.Uint64(m[16:24])
	d ^= binary.LittleEndian.Uint64(m[24:32])

	a, b, c, d = gostPsi64(a, b, c, d)

	a ^= binary.LittleEndian.Uint64(h[0:8])
	b ^= binary.LittleEndian.Uint64(h[8:16])
	c ^= binary.LittleEndian.Uint64(h[16:24])
	d ^= binary.LittleEndian.Uint64(h[24:32])

	for i := 0; i < 61; i++ {
		a, b, c, d = gostPsi64(a, b, c, d)
	}

	binary.LittleEndian.PutUint64(s[0:8], a)
	binary.LittleEndian.PutUint64(s[8:16], b)
	binary.LittleEndian.PutUint64(s[16:24], c)
	binary.LittleEndian.PutUint64(s[24:32], d)
}

// gostPsi64 is gostPsi applied to four little-endian uint64 words. Each uint64
// holds four 16-bit words; psi shifts the stream left by one 16-bit word and
// feeds the top slot with the XOR of words 0,1,2,3,12,15.
func gostPsi64(a, b, c, d uint64) (uint64, uint64, uint64, uint64) {
	// Words 0..3 live in a; fold them into the low 16 bits via xor-shift.
	newWord := (a ^ (a >> 16) ^ (a >> 32) ^ (a >> 48)) & 0xffff
	newWord ^= d & 0xffff         // word 12
	newWord ^= (d >> 48) & 0xffff // word 15

	return (a >> 16) | (b << 48),
		(b >> 16) | (c << 48),
		(c >> 16) | (d << 48),
		(d >> 16) | (newWord << 48)
}
