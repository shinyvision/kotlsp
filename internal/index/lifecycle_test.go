package index

import (
	"context"
	"testing"
	"time"
)

func TestCloseCancelsAndWaitsForRegisteredBackgroundWork(t *testing.T) {
	idx := New(nil)
	workCtx, finish, started := idx.beginBackground(context.Background())
	if !started {
		t.Fatal("background work was rejected before close")
	}
	release := make(chan struct{})
	observedCancellation := make(chan struct{})
	go func() {
		<-workCtx.Done()
		close(observedCancellation)
		<-release
		finish()
	}()
	closed := make(chan struct{})
	go func() {
		idx.Close()
		close(closed)
	}()
	select {
	case <-observedCancellation:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel registered work")
	}
	select {
	case <-closed:
		t.Fatal("Close returned before registered work finished")
	default:
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after registered work exited")
	}
	if _, finishLate, accepted := idx.beginBackground(context.Background()); accepted {
		finishLate()
		t.Fatal("closed index accepted new background work")
	}
}
