package dap

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestServerCloseWaitsForAcceptedConnections(t *testing.T) {
	server, err := Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(server.Port())))
	if err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	defer connection.Close()
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	if err := writeMessage(writer, message{Seq: 1, Type: "request", Command: "initialize", Arguments: json.RawMessage(`{}`)}); err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	if _, err := readMessage(reader); err != nil {
		_ = server.Close()
		t.Fatalf("initialize response: %v", err)
	}
	// DAP requires the initialized event immediately after the initialize
	// response. Consume it before asserting that Close tears down the socket;
	// bytes already buffered by the client cannot be retracted by TCP close.
	if _, err := readMessage(reader); err != nil {
		_ = server.Close()
		t.Fatalf("initialized event: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server Close did not release and join an accepted connection")
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("accepted connection remained readable after server Close")
	}
}
