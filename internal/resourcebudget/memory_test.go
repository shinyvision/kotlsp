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
	// The effective limit is whichever of the two ceilings binds: the envelope
	// less what child JVMs hold, or Go's own limit. Asserting only the former
	// described one set of constants rather than the rule, and stopped holding
	// the moment the envelope grew past the Go limit.
	wantEffective := ProcessTreeSoftLimitBytes - wantCurrent
	if wantEffective > GoSoftLimitBytes {
		wantEffective = GoSoftLimitBytes
	}
	if wantEffective < GoMinimumLimitBytes {
		wantEffective = GoMinimumLimitBytes
	}
	if snapshot.EffectiveGoSoftLimit != wantEffective {
		t.Fatalf("effective Go limit = %d, want %d", snapshot.EffectiveGoSoftLimit, wantEffective)
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
