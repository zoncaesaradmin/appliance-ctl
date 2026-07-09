package images_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/images"
)

// countingRunner fails the first failCount calls (simulating containerd's
// socket not accepting connections yet, the "connection refused" case
// K3s's systemd unit briefly leaves after "started"), then succeeds.
type countingRunner struct {
	failCount int
	calls     int
}

func (r *countingRunner) run(context.Context, string, ...string) (string, error) {
	r.calls++
	if r.calls <= r.failCount {
		return "", errors.New(`ctr: failed to dial "/run/k3s/containerd/containerd.sock": connection refused`)
	}
	return "", nil
}

func TestWaitReady_SucceedsImmediatelyWhenAlreadyUp(t *testing.T) {
	runner := &countingRunner{failCount: 0}
	imp := &images.Importer{Run: runner.run, Namespace: "k8s.io"}

	if err := imp.WaitReady(context.Background(), time.Second, time.Millisecond); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if runner.calls != 1 {
		t.Errorf("expected exactly one attempt, got %d", runner.calls)
	}
}

func TestWaitReady_RetriesUntilContainerdComesUp(t *testing.T) {
	runner := &countingRunner{failCount: 3}
	imp := &images.Importer{Run: runner.run, Namespace: "k8s.io"}

	if err := imp.WaitReady(context.Background(), time.Second, time.Millisecond); err != nil {
		t.Fatalf("expected WaitReady to eventually succeed, got %v", err)
	}
	if runner.calls != 4 {
		t.Errorf("expected 4 attempts (3 failures + 1 success), got %d", runner.calls)
	}
}

func TestWaitReady_TimesOutIfContainerdNeverComesUp(t *testing.T) {
	runner := &countingRunner{failCount: 1000}
	imp := &images.Importer{Run: runner.run, Namespace: "k8s.io"}

	start := time.Now()
	err := imp.WaitReady(context.Background(), 20*time.Millisecond, 5*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("expected WaitReady to give up close to the timeout, took %s", elapsed)
	}
	if runner.calls < 2 {
		t.Errorf("expected more than one attempt before timing out, got %d", runner.calls)
	}
}

func TestWaitReady_RespectsContextCancellation(t *testing.T) {
	runner := &countingRunner{failCount: 1000}
	imp := &images.Importer{Run: runner.run, Namespace: "k8s.io"}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := imp.WaitReady(ctx, time.Minute, 5*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from context cancellation, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("expected WaitReady to return promptly after cancellation, took %s", elapsed)
	}
}
