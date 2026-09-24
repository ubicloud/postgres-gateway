package main

import (
	"testing"
	"time"
)

func TestAcquireEnforcesTheCap(t *testing.T) {
	tracker := newActivityTracker(2)
	now := time.Now()
	for i := 1; i <= 2; i++ {
		if !tracker.acquire("sb1", now) {
			t.Fatalf("connection %d should be allowed", i)
		}
	}
	if tracker.acquire("sb1", now) {
		t.Error("the third connection should be refused")
	}
	if got := tracker.connections("sb1"); got != 2 {
		t.Errorf("connections = %d, want 2 (a refused connection must not count)", got)
	}
	tracker.release("sb1", now)
	if !tracker.acquire("sb1", now) {
		t.Error("a slot should be free after a release")
	}
}

func TestCapIsPerCell(t *testing.T) {
	tracker := newActivityTracker(1)
	now := time.Now()
	if !tracker.acquire("sb1", now) || !tracker.acquire("sb2", now) {
		t.Error("the cap must not be shared between cells")
	}
}

func TestDrainResetsBytesAndForgetsIdleCells(t *testing.T) {
	tracker := newActivityTracker(10)
	now := time.Now()
	tracker.acquire("busy", now)
	tracker.addBytes("busy", 100, now)
	tracker.addBytes("gone", 50, now)

	reports := tracker.drain()
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}

	// Second drain: "busy" still holds a connection so it is still reported,
	// with its byte counter reset; "gone" has neither and is forgotten.
	reports = tracker.drain()
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d: %+v", len(reports), reports)
	}
	if reports[0].CellID != "busy" {
		t.Errorf("reported %q", reports[0].CellID)
	}
	if reports[0].Bytes != 0 {
		t.Errorf("bytes should have been reset, got %d", reports[0].Bytes)
	}
	if tracker.tracked() != 1 {
		t.Errorf("expected the idle cell to be forgotten, %d remain", tracker.tracked())
	}
}

func TestDrainRecordsLastActivity(t *testing.T) {
	tracker := newActivityTracker(10)
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	tracker.acquire("sb1", at)
	reports := tracker.drain()
	if len(reports) != 1 {
		t.Fatalf("expected 1 report")
	}
	if !reports[0].LastActivityAt.Equal(at.UTC()) {
		t.Errorf("last activity = %v, want %v", reports[0].LastActivityAt, at.UTC())
	}
}
