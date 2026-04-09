package anyhash

import (
	"crypto/sha3"
	"hash"
)

func init() {
	registerHash("sha3224", func() Hash { return wrapHash(func() hash.Hash { return sha3.New224() }) })
	registerHash("sha3256", func() Hash { return wrapHash(func() hash.Hash { return sha3.New256() }) })
	registerHash("sha3384", func() Hash { return wrapHash(func() hash.Hash { return sha3.New384() }) })
	registerHash("sha3512", func() Hash { return wrapHash(func() hash.Hash { return sha3.New512() }) })
}
