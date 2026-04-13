package anyhash

import (
	"testing"
)

// benchSizes defines the payload sizes used across throughput benchmarks.
// 64 B exercises finalization-heavy paths; 64 KiB amortizes setup and
// stresses the block-processing loop.
var benchSizes = []struct {
	name string
	n    int
}{
	{"64B", 64},
	{"64KiB", 64 * 1024},
}

// BenchmarkHash runs every registered algorithm across the bench sizes.
// Use -run=^$ -bench=. to skip tests. Filter with -bench=BenchmarkHash/sha256.
func BenchmarkHash(b *testing.B) {
	for _, algo := range List() {
		for _, sz := range benchSizes {
			b.Run(algo+"/"+sz.name, func(b *testing.B) {
				h, err := New(algo)
				if err != nil {
					b.Fatal(err)
				}
				data := make([]byte, sz.n)
				for i := range data {
					data[i] = byte(i)
				}
				b.SetBytes(int64(sz.n))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					h.Reset()
					h.Write(data)
					_ = h.Sum(nil)
				}
			})
		}
	}
}
