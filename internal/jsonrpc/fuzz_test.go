package jsonrpc

import (
	"bufio"
	"bytes"
	"testing"
)

func FuzzJSONRPCFrame(f *testing.F) {
	f.Add([]byte("Content-Length: 38\r\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}"))
	f.Add([]byte("Content-Length: 999999999999999999999\r\n\r\n{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxMessageBytes+maxHeaderLineBytes+32 {
			t.Skip()
		}
		connection := &Conn{r: bufio.NewReaderSize(bytes.NewReader(data), maxHeaderLineBytes+1)}
		_, _ = connection.read()
	})
}
