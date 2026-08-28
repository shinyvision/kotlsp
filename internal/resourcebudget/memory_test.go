package resourcebudget

import (
	"context"
	"testing"
	"time"
)

func TestReservationsShareOneProcessTreeBudget(t *testing.T) {
	host, err := Acquire(context.Background(), "host-test", CompilerHostBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer host()
	oneShot, err := Acquire(context.Background(), "oneshot-test", CompilerOneShotBytes)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := Current()
	wantCurrent := CompilerHostBytes + CompilerOneShotBytes
	if snapshot.ToolCurrent != wantCurrent {
		t.Fatalf("tool reservation = %d, want %d", snapshot.ToolCurrent, wantCurrent)
	}
	if snapshot.EffectiveGoSoftLimit != ProcessTreeSoftLimitBytes-wantCurrent {
		t.Fatalf("effective Go limit = %d", snapshot.EffectiveGoSoftLimit)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, acquireErr := Acquire(ctx, "blocked-test", BuildToolBytes); acquireErr == nil {
		t.Fatal("overlapping child tools exceeded the shared process-tree budget")
	}
	oneShot()
	build, err := Acquire(context.Background(), "build-test", BuildToolBytes)
	if err != nil {
		t.Fatal(err)
	}
	build()
}
