package anyhash

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"
)

// PHP-compatible test vectors: hash of ""
var emptyVectors = map[string]string{
	"md2":        "8350e5a3e24c153df2275c9f80692773",
	"md4":        "31d6cfe0d16ae931b73c59d7e0c089c0",
	"md5":        "d41d8cd98f00b204e9800998ecf8427e",
	"sha1":       "da39a3ee5e6b4b0d3255bfef95601890afd80709",
	"sha224":     "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
	"sha256":     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"sha384":     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
	"sha512":     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	"sha512/224": "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
	"sha512/256": "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
	"sha3-224":   "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
	"sha3-256":   "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
	"sha3-384":   "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
	"sha3-512":   "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
	"ripemd128":  "cdf26213a150dc3ecb610f18f6b38b46",
	"ripemd160":  "9c1185a5c5e9fc54612808977ee8f548b2258d31",
	"ripemd256":  "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
	"ripemd320":  "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
	"whirlpool":  "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
	"tiger128,3": "3293ac630c13f0245f92bbb1766e1616",
	"tiger160,3": "3293ac630c13f0245f92bbb1766e16167a4e5849",
	"tiger192,3": "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3",
	"tiger128,4": "24cc78a7f6ff3546e7984e59695ca13d",
	"tiger160,4": "24cc78a7f6ff3546e7984e59695ca13d804e0b68",
	"tiger192,4": "24cc78a7f6ff3546e7984e59695ca13d804e0b686e255194",
	"snefru":     "8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881",
	"snefru256":  "8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881",
	"gost":       "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d",
	"gost-crypto": "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0",
	"adler32":    "00000001",
	"crc32":      "00000000",
	"crc32b":     "00000000",
	"crc32c":     "00000000",
	"fnv132":     "811c9dc5",
	"fnv1a32":    "811c9dc5",
	"fnv164":     "cbf29ce484222325",
	"fnv1a64":    "cbf29ce484222325",
	"joaat":      "00000000",
	"murmur3a":   "00000000",
	"murmur3c":   "00000000000000000000000000000000",
	"murmur3f":   "00000000000000000000000000000000",
	"xxh32":      "02cc5d05",
	"xxh64":      "ef46db3751d8e999",
	"xxh3":       "2d06800538d394c2",
	"xxh128":     "99aa06d3014798d86001c324468d497f",
	"haval128,3": "c68f39913f901f3ddf44c707357a7d70",
	"haval160,3": "d353c3ae22a25401d257643836d7231a9a95f953",
	"haval192,3": "e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e",
	"haval224,3": "c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d",
	"haval256,3": "4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17",
	"haval128,4": "ee6bbf4d6a46a679b3a856c88538bb98",
	"haval160,4": "1d33aae1be4146dbaaca0b6e70d7a11f10801525",
	"haval192,4": "4a8372945afa55c7dead800311272523ca19d42ea47b72da",
	"haval224,4": "3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e",
	"haval256,4": "c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b",
	"haval128,5": "184b8482a0c050dca54b59c7f05bf5dd",
	"haval160,5": "255158cfc1eed1a7be7c55ddd64d9790415b933b",
	"haval192,5": "4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85",
	"haval224,5": "4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e",
	"haval256,5": "be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330",
}

// PHP-compatible test vectors: hash of "abc"
var abcVectors = map[string]string{
	"md2":        "da853b0d3f88d99b30283a69e6ded6bb",
	"md4":        "a448017aaf21d8525fc10ae87aa6729d",
	"md5":        "900150983cd24fb0d6963f7d28e17f72",
	"sha1":       "a9993e364706816aba3e25717850c26c9cd0d89d",
	"sha224":     "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
	"sha256":     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	"sha384":     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	"sha512":     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	"sha512/224": "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
	"sha512/256": "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
	"sha3-224":   "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
	"sha3-256":   "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
	"sha3-384":   "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
	"sha3-512":   "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
	"ripemd128":  "c14a12199c66e4ba84636b0f69144c77",
	"ripemd160":  "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
	"ripemd256":  "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
	"ripemd320":  "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
	"whirlpool":  "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
	"tiger128,3": "2aab1484e8c158f2bfb8c5ff41b57a52",
	"tiger160,3": "2aab1484e8c158f2bfb8c5ff41b57a525129131c",
	"tiger192,3": "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93",
	"tiger128,4": "538883c8fc5f28250299018e66bdf4fd",
	"tiger160,4": "538883c8fc5f28250299018e66bdf4fdb5ef7b65",
	"tiger192,4": "538883c8fc5f28250299018e66bdf4fdb5ef7b65f2e91753",
	"snefru":     "7d033205647a2af3dc8339f6cb25643c33ebc622d32979c4b612b02c4903031b",
	"snefru256":  "7d033205647a2af3dc8339f6cb25643c33ebc622d32979c4b612b02c4903031b",
	"gost":       "f3134348c44fb1b2a277729e2285ebb5cb5e0f29c975bc753b70497c06a4d51d",
	"gost-crypto": "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c",
	"adler32":    "024d0127",
	"crc32":      "73bb8c64",
	"crc32b":     "352441c2",
	"crc32c":     "364b3fb7",
	"fnv132":     "439c2f4b",
	"fnv1a32":    "1a47e90b",
	"fnv164":     "d8dcca186bafadcb",
	"fnv1a64":    "e71fa2190541574b",
	"joaat":      "ed131f5b",
	"murmur3a":   "b3dd93fa",
	"murmur3c":   "75cdc6d1a2b006a5a2b006a5a2b006a5",
	"murmur3f":   "b4963f3f3fad78673ba2744126ca2d52",
	"xxh32":      "32d153ff",
	"xxh64":      "44bc2cf5ad770999",
	"xxh3":       "78af5f94892f3950",
	"xxh128":     "06b05ab6733a618578af5f94892f3950",
	"haval128,3": "9e40ed883fb63e985d299b40cda2b8f2",
	"haval160,3": "b21e876c4d391e2a897661149d83576b5530a089",
	"haval192,3": "a7b14c9ef3092319b0e75e3b20b957d180bf20745629e8de",
	"haval224,3": "5bc955220ba2346a948d2848eca37bdd5eca6ecca7b594bd32923fab",
	"haval256,3": "8699f1e3384d05b2a84b032693e2b6f46df85a13a50d93808d6874bb8fb9e86c",
	"haval128,4": "6f2132867c9648419adcd5013e532fa2",
	"haval160,4": "77aca22f5b12cc09010afc9c0797308638b1cb9b",
	"haval192,4": "7e29881ed05c915903dd5e24a8e81cde5d910142ae66207c",
	"haval224,4": "124c43d2ba4884599d013e8c872bfea4c88b0b6bf6303974cbe04e68",
	"haval256,4": "8f409f1bb6b30c5016fdce55f652642261575bedca0b9533f32f5455459142b5",
	"haval128,5": "d054232fe874d9c6c6dc8e6a853519ea",
	"haval160,5": "ae646b04845e3351f00c5161d138940e1fa0c11c",
	"haval192,5": "d12091104555b00119a8d07808a3380bf9e60018915b9025",
	"haval224,5": "8081027a500147c512e5f1055986674d746d92af4841abeb89da64ad",
	"haval256,5": "976cd6254c337969e5913b158392a2921af16fca51f5601d486e0a9de01156e7",
}

func TestEmptyHash(t *testing.T) {
	for algo, want := range emptyVectors {
		h, err := New(algo)
		if err != nil {
			t.Fatalf("New(%q): %v", algo, err)
		}
		got := hex.EncodeToString(h.Sum(nil))
		if got != want {
			t.Errorf("%s(\"\") = %s, want %s", algo, got, want)
		}
	}
}

func TestABCHash(t *testing.T) {
	for algo, want := range abcVectors {
		h, err := New(algo)
		if err != nil {
			t.Fatalf("New(%q): %v", algo, err)
		}
		h.Write([]byte("abc"))
		got := hex.EncodeToString(h.Sum(nil))
		if got != want {
			t.Errorf("%s(\"abc\") = %s, want %s", algo, got, want)
		}
	}
}

// hash of "abd" — used to verify clone produces correct divergent output
var abdVectors = map[string]string{
	"md2":        "4cd4912350b603130cff1764edeed529",
	"md4":        "c21041d9843243088343c54249944165",
	"md5":        "4911e516e5aa21d327512e0c8b197616",
	"sha1":       "cb4cc28df0fdbe0ecf9d9662e294b118092a5735",
	"sha224":     "9a7b7e67edba75ffa6c9f139c319ca3b5e9cf99cb36979d3c33bf2c8",
	"sha256":     "a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9",
	"sha384":     "5d15bcebb965fa77926c23471c96e3a326b363f5f105c3ef17cfd033b9734fa46556f81a26bb3044d2dda50481325ef7",
	"sha512":     "1a9840c27a5cf22dab060cdd8a83da2b0fbcb1aeb52d4f9d3894b639083e205a5ab3f6afaeeb21b8e99b5e0fe93daafaabeef274da5d6eadcc9db36e5b6f64c4",
	"sha512/224": "0d436de70887fe8e0a25cf9ae7040b74d78d522160e3919168e1bc34",
	"sha512/256": "72e5b67ed56db92b5d793c8610219bcb2e6c3fb70ac6a729fee72109b95498e8",
	"sha3-224":   "480eed714c30bb7869dc83bd4fa58c4cae6c4fe8d116e580eb7237dc",
	"sha3-256":   "f5f119fa0e57ad6839cdcd08902827a07120b6cf490e34af8f12144dc0dcec45",
	"sha3-384":   "4e4b54a7b664b646cdafc626b3f01e79021628b9654bfd2a779dd6709d821d90ac2211d024f445f1ca6534b2b6977059",
	"sha3-512":   "6870015a2b04aaee34a75ad4f02f7e8dc864137c753da70b693df9ec3f2c0d000092d36aad87bf76d53cc0af5246d50175bf5aca9a608d8edb77970adee7bb85",
	"ripemd128":  "7b9fc243737d9f08df0aa53d9a5deb96",
	"ripemd160":  "b0a79cc77e333ea11974e105cd051d33836928b0",
	"ripemd256":  "bf5501059851736c7c850692510a845848a8430ba332c7076b9bfcc711174105",
	"ripemd320":  "48146ac1f0fdf2b30a2d1754486caf8a01bc2ba0921145ab3569d0e5052f3a749e3ee39ad29f54b2",
	"whirlpool":  "112fb44910e676f5dcb02f193a46283575ea4d29f2aadf545d8f228266c1faf8987edbc9361d11f04bbe8d868b084f9eac0b79d3fd2fc113e5239bd8755cf293",
	"tiger128,3": "b69798e309bb741dfb4b58e7ac77c77e",
	"tiger160,3": "b69798e309bb741dfb4b58e7ac77c77e74f7c6c5",
	"tiger192,3": "b69798e309bb741dfb4b58e7ac77c77e74f7c6c56ccb8795",
	"tiger128,4": "1218a21c97572bbd3722c5f087e688de",
	"tiger160,4": "1218a21c97572bbd3722c5f087e688dea6448ff7",
	"tiger192,4": "1218a21c97572bbd3722c5f087e688dea6448ff7f3d09078",
	"snefru":     "a204aa328d61434cdb534e4f24a64e138630c8fff8e8224d46bf3ecabdf1442a",
	"snefru256":  "a204aa328d61434cdb534e4f24a64e138630c8fff8e8224d46bf3ecabdf1442a",
	"gost":       "4f0be3b4f2cf9916604eee4f4559839c93856e869ee765ff686d185825d78c25",
	"gost-crypto": "7eb91039cc904c8c299a95acc596169a250f0f8457ff4a587e8d981cdc9dc3bb",
	"adler32":    "024e0128",
	"crc32":      "76ebcb7a",
	"crc32b":     "ab40d461",
	"crc32c":     "e2815b5c",
	"fnv132":     "439c2f4c",
	"fnv1a32":    "1f47f0ea",
	"fnv164":     "d8dcca186bafadcc",
	"fnv1a64":    "e71fa71905415fca",
	"joaat":      "1b4cfbce",
	"murmur3a":   "b6dc2c1a",
	"murmur3c":   "fb1c417ffe181eadfe181eadfe181ead",
	"murmur3f":   "6e36f626f40a629aafe88dbd4af8ee67",
	"xxh32":      "d8160112",
	"xxh64":      "6a8740cb78d5c8d2",
	"xxh3":       "6b4467b443c76228",
	"xxh128":     "ec4af3fc0b1f44fe6b4467b443c76228",
	"haval128,3": "01c0a017588c9a7bf013fb4d1503475f",
	"haval160,3": "77a33d8cf109cd9fcaa400099ff0609681360406",
	"haval192,3": "d7214463abb855e1d76657b9bd4e9a9b2548b1f2168b2db7",
	"haval224,3": "55f0ece652e355a110260743d6b75306e9fd7b7e526474ed5ac441f3",
	"haval256,3": "1bff48aa4f99b290936967198484d6ba354fc2c576b82e942fde984f8349c39b",
	"haval128,4": "50ae11b11e1b1cfad3a14defea791153",
	"haval160,4": "31124b9bba4a2a4719901a12b95413bd92c34aa9",
	"haval192,4": "89c3ca235a1d9d603f711ede3b9f39df465595f8dc77ea75",
	"haval224,4": "16fa7100672bc67f378906d1c8574ec874e75e22c36cd6526a2d1c8a",
	"haval256,4": "a4a384d7e2191ba6e02b4a4061175a0b0103e1cd710bc879c69659b0dcd2e674",
	"haval128,5": "d69789a44f02a85c3512109377f1f5ce",
	"haval160,5": "27f0526eb30acdc6e10aba45eeceeb99e547e50e",
	"haval192,5": "dd4a48beb4c4b71a97716bb119f0f2150b021c6760d4930f",
	"haval224,5": "712b65d7aa5cf238fc0644ac7c649b6dd7189ae56405621c53ed1dc5",
	"haval256,5": "b4d350a348a6453abc24e3089c790655323942a70bc3758efb76d7e5277197f4",
}

func TestClone(t *testing.T) {
	for algo, wantABC := range abcVectors {
		h, err := New(algo)
		if err != nil {
			t.Fatal(err)
		}
		h.Write([]byte("ab"))

		// Clone after "ab"
		h2 := h.Clone()

		// Original: finish with "c" → should match "abc" vector
		h.Write([]byte("c"))
		got := hex.EncodeToString(h.Sum(nil))
		if got != wantABC {
			t.Errorf("clone test %s: original got %s, want %s", algo, got, wantABC)
		}

		// Clone: finish with "d" → should match "abd" vector
		h2.Write([]byte("d"))
		got2 := hex.EncodeToString(h2.Sum(nil))
		wantABD := abdVectors[algo]
		if got2 != wantABD {
			t.Errorf("clone test %s: cloned got %s, want %s", algo, got2, wantABD)
		}
	}
}

func TestContinueAfterSum(t *testing.T) {
	for algo := range abcVectors {
		h, err := New(algo)
		if err != nil {
			t.Fatal(err)
		}
		h.Write([]byte("a"))
		_ = h.Sum(nil) // compute intermediate hash
		h.Write([]byte("bc"))

		got := hex.EncodeToString(h.Sum(nil))
		want := abcVectors[algo]
		if got != want {
			t.Errorf("continue-after-sum %s: got %s, want %s", algo, got, want)
		}
	}
}

func TestNormalization(t *testing.T) {
	cases := []string{"SHA-256", "sha256", "SHA256", "Sha-256"}
	for _, name := range cases {
		h, err := New(name)
		if err != nil {
			t.Errorf("New(%q) failed: %v", name, err)
			continue
		}
		got := hex.EncodeToString(h.Sum(nil))
		if got != emptyVectors["sha256"] {
			t.Errorf("New(%q) hash mismatch", name)
		}
	}
}

func TestUnknownAlgo(t *testing.T) {
	_, err := New("bogus")
	if err == nil {
		t.Error("New(\"bogus\") should return error")
	}
}

func TestList(t *testing.T) {
	list := List()
	if !slices.IsSorted(list) {
		t.Error("List() should return sorted names")
	}
	// Check a few expected entries are present.
	for _, want := range []string{"md5", "sha1", "sha256", "sha512/256"} {
		if !slices.Contains(list, want) {
			t.Errorf("List() missing %q", want)
		}
	}
}

func TestHMAC(t *testing.T) {
	key := []byte("secret-key")
	msg := []byte("hello world")

	// Compute reference with stdlib crypto/hmac + sha256.
	ref := hmac.New(sha256.New, key)
	ref.Write(msg)
	want := hex.EncodeToString(ref.Sum(nil))

	// Compute with anyhash.
	h, err := NewHMAC("sha256", key)
	if err != nil {
		t.Fatal(err)
	}
	h.Write(msg)
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Errorf("HMAC-SHA256 got %s, want %s", got, want)
	}
}

func TestHMACClone(t *testing.T) {
	key := []byte("key")

	h, err := NewHMAC("sha256", key)
	if err != nil {
		t.Fatal(err)
	}
	h.Write([]byte("ab"))
	h2 := h.Clone()

	// Original: "abc"
	h.Write([]byte("c"))
	sum1 := hex.EncodeToString(h.Sum(nil))

	// Clone: "abd"
	h2.Write([]byte("d"))
	sum2 := hex.EncodeToString(h2.Sum(nil))

	if sum1 == sum2 {
		t.Error("HMAC clone should produce different results for different data")
	}

	// Verify original matches a fresh HMAC of "abc".
	fresh, _ := NewHMAC("sha256", key)
	fresh.Write([]byte("abc"))
	wantABC := hex.EncodeToString(fresh.Sum(nil))
	if sum1 != wantABC {
		t.Errorf("HMAC clone: original got %s, want %s", sum1, wantABC)
	}

	// Verify clone matches a fresh HMAC of "abd".
	fresh2, _ := NewHMAC("sha256", key)
	fresh2.Write([]byte("abd"))
	wantABD := hex.EncodeToString(fresh2.Sum(nil))
	if sum2 != wantABD {
		t.Errorf("HMAC clone: cloned got %s, want %s", sum2, wantABD)
	}
}

func TestHMACContinueAfterSum(t *testing.T) {
	key := []byte("key")

	h, err := NewHMAC("sha256", key)
	if err != nil {
		t.Fatal(err)
	}
	h.Write([]byte("a"))
	_ = h.Sum(nil) // intermediate
	h.Write([]byte("bc"))
	got := hex.EncodeToString(h.Sum(nil))

	fresh, _ := NewHMAC("sha256", key)
	fresh.Write([]byte("abc"))
	want := hex.EncodeToString(fresh.Sum(nil))

	if got != want {
		t.Errorf("HMAC continue-after-sum: got %s, want %s", got, want)
	}
}

func TestHMACReset(t *testing.T) {
	key := []byte("key")
	h, err := NewHMAC("sha256", key)
	if err != nil {
		t.Fatal(err)
	}
	h.Write([]byte("garbage"))
	h.Reset()
	h.Write([]byte("abc"))
	got := hex.EncodeToString(h.Sum(nil))

	fresh, _ := NewHMAC("sha256", key)
	fresh.Write([]byte("abc"))
	want := hex.EncodeToString(fresh.Sum(nil))

	if got != want {
		t.Errorf("HMAC reset: got %s, want %s", got, want)
	}
}

// RFC 5869 test vectors.
func TestHKDF(t *testing.T) {
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	tests := []struct {
		name   string
		algo   string
		ikm    []byte
		salt   []byte
		info   []byte
		length int
		okm    string
	}{
		{
			name:   "RFC5869 Test Case 1",
			algo:   "sha256",
			ikm:    mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
			salt:   mustHex("000102030405060708090a0b0c"),
			info:   mustHex("f0f1f2f3f4f5f6f7f8f9"),
			length: 42,
			okm:    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name:   "RFC5869 Test Case 2",
			algo:   "sha256",
			ikm:    mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
			salt:   mustHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
			info:   mustHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
			length: 82,
			okm:    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		{
			name:   "RFC5869 Test Case 3",
			algo:   "sha256",
			ikm:    mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
			salt:   nil,
			info:   nil,
			length: 42,
			okm:    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewHKDF(tc.algo, tc.ikm, tc.length, tc.info, tc.salt)
			if err != nil {
				t.Fatal(err)
			}
			gotHex := hex.EncodeToString(got)
			if gotHex != tc.okm {
				t.Errorf("got  %s\nwant %s", gotHex, tc.okm)
			}
		})
	}
}
