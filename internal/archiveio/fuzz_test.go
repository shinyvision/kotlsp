package archiveio

import (
	"archive/zip"
	"bytes"
	"testing"
)

func FuzzZipEntryLimits(f *testing.F) {
	f.Add([]byte("PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4<<20 {
			t.Skip()
		}
		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		budget, err := NewBudget(reader.File)
		if err != nil {
			return
		}
		for index, entry := range reader.File {
			if index >= 64 {
				break
			}
			_, _ = budget.Read(entry, 1<<20)
		}
	})
}
