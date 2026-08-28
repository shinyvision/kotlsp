package dap

import (
	"bufio"
	"bytes"
	"testing"
)

func FuzzDAPFrameAndText(f *testing.F) {
	f.Add([]byte("Content-Length: 2\r\n\r\n{}"))
	f.Add([]byte("Breakpoint hit: thread=main, demo.Main.run(), line=12"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16<<20+8192 {
			t.Skip()
		}
		_, _ = readMessage(bufio.NewReader(bytes.NewReader(data)))
		text := string(data)
		_ = decodeBridgeRows(text)
		_ = childExpression(text, text)
	})
}
