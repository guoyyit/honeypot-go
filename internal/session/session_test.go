package session

import (
	"context"
	"testing"
)

func TestAppendAndReplay(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir, 1000)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	sess := &Session{ID: "sess-1", Service: "web", Kind: "http", Listen: "127.0.0.1:1", Source: "127.0.0.1:9"}
	if err := store.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	rec := NewRecorder(store, sess.ID, 10)
	if err := rec.In(ctx, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := rec.Out(ctx, []byte("xy")); err != nil {
		t.Fatal(err)
	}
	if err := rec.SetFingerprint(ctx, "nmap-http"); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(ctx, ReasonVal()); err != nil {
		t.Fatal(err)
	}

	// 重新打开同一目录（模拟重启）
	store2, err := NewFileStore(dir, 1000)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store2.Get("sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != "nmap-http" {
		t.Fatalf("fingerprint=%q", got.Fingerprint)
	}
	if got.ClosedReason != "done" || got.EndedAt == nil {
		t.Fatalf("end not recovered: reason=%q ended=%v", got.ClosedReason, got.EndedAt)
	}
	if len(got.Events) != 2 {
		t.Fatalf("want 2 events, got %d", len(got.Events))
	}
	if string(got.Events[0].Decode()) != "abc" || string(got.Events[1].Decode()) != "xy" {
		t.Fatalf("payloads mismatch: %q %q", got.Events[0].Decode(), got.Events[1].Decode())
	}
	if got.Events[0].Seq != 0 || got.Events[1].Seq != 1 {
		t.Fatalf("seq must be contiguous: %d %d", got.Events[0].Seq, got.Events[1].Seq)
	}
}

func TestByteLimitTruncation(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileStore(dir, 1000)
	ctx := context.Background()
	sess := &Session{ID: "sess-2", Service: "raw", Kind: "tcp"}
	if err := store.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	rec := NewRecorder(store, sess.ID, 5)
	if err := rec.In(ctx, []byte("12345")); err != nil {
		t.Fatal(err)
	}
	// 超出上限：仍产生事件，但载荷被截断且带 note
	if err := rec.In(ctx, []byte("67890")); err != nil {
		t.Fatal(err)
	}
	rec.Close(ctx, "done")

	full, err := store.Get("sess-2")
	if err != nil {
		t.Fatal(err)
	}
	var total int
	var sawTrunc bool
	for _, ev := range full.Events {
		total += len(ev.Decode())
		if ev.Note != "" {
			sawTrunc = true
		}
	}
	if total != 5 {
		t.Fatalf("persisted payload must be capped at 5, got %d", total)
	}
	if !sawTrunc {
		t.Fatal("expected truncation note")
	}
}

func TestGlobalRecordLimit(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileStore(dir, 2)
	ctx := context.Background()
	sess := &Session{ID: "sess-3", Kind: "tcp"}
	if err := store.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	rec := NewRecorder(store, sess.ID, 1<<20)
	if err := rec.In(ctx, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := rec.In(ctx, []byte("b")); err != nil {
		t.Fatal(err)
	}
	err := rec.In(ctx, []byte("c"))
	if err != ErrRecordLimit {
		t.Fatalf("want ErrRecordLimit, got %v", err)
	}
}

func TestEndIdempotentAndClosedWrites(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileStore(dir, 100)
	sess := &Session{ID: "sess-4", Kind: "tcp"}
	if err := store.CreateSession(sess); err != nil {
		t.Fatal(err)
	}
	if err := store.EndSession("sess-4", "done"); err != nil {
		t.Fatal(err)
	}
	if err := store.EndSession("sess-4", "done"); err != nil {
		t.Fatalf("double end should be idempotent: %v", err)
	}
	if err := store.AppendEvent("sess-4", &Event{Dir: DirIn}); err != ErrSessionClosed {
		t.Fatalf("write after end must fail, got %v", err)
	}
	if _, err := store.Get("missing"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func ReasonVal() string { return "done" }
