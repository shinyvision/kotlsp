package classfile

import "testing"

func FuzzClassfile(f *testing.F) {
	f.Add([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61, 0, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<20 {
			t.Skip()
		}
		parsed, _ := Parse(data)
		if parsed != nil {
			_ = RenderJava(parsed)
		}
	})
}
