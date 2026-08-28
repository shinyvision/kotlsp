package index

import "testing"

func FuzzKotlinMetadataWire(f *testing.F) {
	f.Add([]byte{0x08, 0x01, 0x12, 0x03, 'A', 'n', 'y'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		protobufFields(data, func(int, int, uint64, []byte) {})
		_, _ = decodeKotlinMetadataType(data)
		_, _ = decodeKotlinMetadataParameter(data, nil)
	})
}
