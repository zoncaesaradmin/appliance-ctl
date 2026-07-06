package lifecycle_test

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zoncaesaradmin/appliance-ctl/internal/lifecycle"
)

func TestAcquireLock_ExclusiveAcrossHolders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installer.lock")

	first, err := lifecycle.AcquireLock(path)
	if err != nil {
		t.Fatalf("expected first acquire to succeed, got: %v", err)
	}

	if _, err := lifecycle.AcquireLock(path); err == nil {
		t.Error("expected second acquire to fail while the first holder is active")
	}

	if err := first.Release(); err != nil {
		t.Fatalf("release failed: %v", err)
	}

	second, err := lifecycle.AcquireLock(path)
	if err != nil {
		t.Fatalf("expected acquire to succeed after release, got: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatalf("release failed: %v", err)
	}
}

// Race/concurrency guard: many goroutines repeatedly contend for the same
// lock; at most one may ever believe it holds it at a time. Run with
// `go test -race` to also catch any unsynchronized access to shared state.
func TestAcquireLock_MutualExclusionUnderConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installer.lock")

	var holders int32
	var violations int32
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				l, err := lifecycle.AcquireLock(path)
				if err != nil {
					continue // expected under contention
				}
				if n := atomic.AddInt32(&holders, 1); n != 1 {
					atomic.AddInt32(&violations, 1)
				}
				time.Sleep(time.Millisecond)
				atomic.AddInt32(&holders, -1)
				if err := l.Release(); err != nil {
					t.Errorf("release failed: %v", err)
				}
			}
		}()
	}
	wg.Wait()

	if violations > 0 {
		t.Errorf("mutual exclusion violated %d time(s): more than one goroutine held the lock simultaneously", violations)
	}
}
