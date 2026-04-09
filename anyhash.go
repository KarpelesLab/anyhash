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
	"md5":        func() Hash { return wrapHash(md5.New) },
	"sha1":       func() Hash { return wrapHash(sha1.New) },
	"sha224":     func() Hash { return wrapHash(sha256.New224) },
	"sha256":     func() Hash { return wrapHash(sha256.New) },
	"sha384":     func() Hash { return wrapHash(sha512.New384) },
	"sha512":     func() Hash { return wrapHash(sha512.New) },
	"sha512/224": func() Hash { return wrapHash(sha512.New512_224) },
	"sha512/256": func() Hash { return wrapHash(sha512.New512_256) },
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
