package log

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countHandler counts the records it handles.
type countHandler struct {
	n atomic.Int64
}

func (*countHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countHandler) Handle(context.Context, slog.Record) error {
	h.n.Add(1)
	return nil
}

func (h *countHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *countHandler) WithGroup(string) slog.Handler { return h }

// Analyzers log from many goroutines before a program initializes the
// logger, through copies of the handler made by With.
func TestDeferredHandler_Concurrent(t *testing.T) {
	const goroutines, records = 8, 1000
	d := newDeferredHandler()
	var wg sync.WaitGroup
	for i := range goroutines {
		h := d.WithAttrs([]slog.Attr{slog.Int("goroutine", i)})
		wg.Go(func() {
			for range records {
				r := slog.NewRecord(time.Time{}, slog.LevelDebug, "record", 0)
				_ = h.Handle(t.Context(), r)
			}
		})
	}
	wg.Wait()

	var c countHandler
	d.Flush(&c)
	if got := c.n.Load(); got != goroutines*records {
		t.Errorf("Flush handled %d records, want %d", got, goroutines*records)
	}
}
