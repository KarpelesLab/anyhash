// Package anyhash provides a unified interface for hash algorithms selected by name.
//
// Unlike Go's standard crypto packages, anyhash lets you specify the algorithm
// as a string and provides a Clone method to duplicate hash state at any point.
package anyhash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding"
	"fmt"
	"hash"
	"sort"
	"strings"
)

// Hash extends hash.Hash with the ability to clone the current state.
type Hash interface {
	hash.Hash
	// Clone returns an independent copy of the hash in its current state.
	Clone() Hash
}

type newFunc func() Hash

var algos = map[string]newFunc{
	"md2":        func() Hash { return newMD2() },
	"md4":        func() Hash { return newMD4() },
	"md5":        func() Hash { return phpWrapHash("md5", md5.New, md5Codec) },
	"sha1":       func() Hash { return phpWrapHash("sha1", sha1.New, sha1Codec) },
	"sha224":     func() Hash { return phpWrapHash("sha224", sha256.New224, sha224Codec) },
	"sha256":     func() Hash { return phpWrapHash("sha256", sha256.New, sha256Codec) },
	"sha384":     func() Hash { return phpWrapHash("sha384", sha512.New384, makeSHA512Codec("sha\x04")) },
	"sha512":     func() Hash { return phpWrapHash("sha512", sha512.New, makeSHA512Codec("sha\x07")) },
	"sha512/224": func() Hash { return phpWrapHash("sha512/224", sha512.New512_224, makeSHA512Codec("sha\x05")) },
	"sha512/256": func() Hash { return phpWrapHash("sha512/256", sha512.New512_256, makeSHA512Codec("sha\x06")) },
}

// registerHash adds an algorithm to the registry. Used by init() functions
// in per-algorithm files.
func registerHash(name string, fn newFunc) {
	algos[name] = fn
}

// normalize lowercases and strips hyphens so that "SHA-256" → "sha256".
func normalize(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "-", "")
}

// List returns the sorted list of supported algorithm names.
func List() []string {
	out := make([]string, 0, len(algos))
	for name := range algos {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// New creates a new Hash for the named algorithm. Algorithm names are
// case-insensitive and hyphens are ignored, so "SHA-256", "sha256", and
// "SHA256" all work.
func New(algo string) (Hash, error) {
	fn, ok := algos[normalize(algo)]
	if !ok {
		return nil, fmt.Errorf("anyhash: unknown algorithm %q", algo)
	}
	return fn(), nil
}

// NewHMAC creates a new HMAC using the named hash algorithm and the given key.
// The returned Hash supports Clone and continue-after-Sum like any other Hash.
func NewHMAC(algo string, key []byte) (Hash, error) {
	fn, ok := algos[normalize(algo)]
	if !ok {
		return nil, fmt.Errorf("anyhash: unknown algorithm %q", algo)
	}
	return newHMAC(fn, key), nil
}

// PHPMarshaler is implemented by hashes that support PHP-compatible state
// serialization. The state is represented as signed int32 values (matching
// PHP's integer representation) plus a raw buffer.
type PHPMarshaler interface {
	// PHPAlgo returns the PHP-compatible algorithm name (e.g. "sha256", "tiger192,3").
	PHPAlgo() string
	// MarshalPHP returns the hash state as PHP-compatible int32 values and a buffer.
	MarshalPHP() ([]int32, []byte)
	// UnmarshalPHP restores the hash state from PHP-compatible int32 values and a buffer.
	UnmarshalPHP(state []int32, buf []byte) error
}

// MarshalPHP serializes a Hash's internal state into PHP-compatible components.
// Returns the PHP algorithm name, state as int32 values, and the buffer.
func MarshalPHP(h Hash) (algo string, state []int32, buf []byte, err error) {
	pm, ok := h.(PHPMarshaler)
	if !ok {
		return "", nil, nil, fmt.Errorf("anyhash: hash does not support PHP marshaling")
	}
	state, buf = pm.MarshalPHP()
	return pm.PHPAlgo(), state, buf, nil
}

// UnmarshalPHP creates a Hash from PHP-compatible serialized state.
// The algo name should be a PHP-compatible name (e.g. "sha256", "tiger192,3").
func UnmarshalPHP(algo string, state []int32, buf []byte) (Hash, error) {
	h, err := New(algo)
	if err != nil {
		return nil, err
	}
	pm, ok := h.(PHPMarshaler)
	if !ok {
		return nil, fmt.Errorf("anyhash: algorithm %q does not support PHP marshaling", algo)
	}
	if err := pm.UnmarshalPHP(state, buf); err != nil {
		return nil, err
	}
	return h, nil
}

// hashWrapper adapts a standard hash.Hash (that supports binary marshaling)
// into the anyhash.Hash interface by adding Clone.
type hashWrapper struct {
	hash.Hash
	make func() hash.Hash
}

func wrapHash(fn func() hash.Hash) *hashWrapper {
	return &hashWrapper{Hash: fn(), make: fn}
}

func (w *hashWrapper) Clone() Hash {
	state, err := w.Hash.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic("anyhash: clone marshal: " + err.Error())
	}
	h := w.make()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		panic("anyhash: clone unmarshal: " + err.Error())
	}
	return &hashWrapper{Hash: h, make: w.make}
}
