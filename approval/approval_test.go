package approval

import (
	"testing"
	"time"
)

func TestFlow(t *testing.T) {
	dir := t.TempDir()
	getenv := func(k string) string {
		if k == "INFRA_APPROVALS_DIR" {
			return dir
		}
		return ""
	}
	now := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	r, ok, err := Ask(getenv, "ship", "deploy", "prod/api", "agent", "t1", "release v2", now)
	if err != nil || ok || r.Status != "pending" || r.ID != ID("ship", "deploy", "prod/api", "agent") {
		t.Fatalf("ask: %+v %v %v", r, ok, err)
	}
	// asking again keeps it pending, same id
	r2, ok, _ := Ask(getenv, "ship", "deploy", "prod/api", "agent", "t2", "", now.Add(time.Minute))
	if ok || r2.ID != r.ID || r2.TokenID != "t2" {
		t.Fatalf("re-ask: %+v", r2)
	}
	list, _ := List(getenv)
	if len(list) != 1 || list[0].Describe() != "ship:deploy prod/api" {
		t.Fatalf("list: %+v", list)
	}
	if _, err := Approve(getenv, r.ID, "timo", time.Hour, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// the next identical call consumes the approval
	r3, ok, err := Ask(getenv, "ship", "deploy", "prod/api", "agent", "t2", "", now.Add(3*time.Minute))
	if err != nil || !ok || r3.Status != "used" {
		t.Fatalf("consume: %+v %v %v", r3, ok, err)
	}
	// once only
	r4, ok, _ := Ask(getenv, "ship", "deploy", "prod/api", "agent", "t2", "", now.Add(4*time.Minute))
	if ok || r4.Status != "pending" {
		t.Fatalf("second use: %+v %v", r4, ok)
	}
	if _, err := Approve(getenv, r.ID, "timo", time.Hour, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// expired approval asks again
	r5, ok, _ := Ask(getenv, "ship", "deploy", "prod/api", "agent", "t2", "", now.Add(3*time.Hour))
	if ok || r5.Status != "pending" {
		t.Fatalf("expired: %+v %v", r5, ok)
	}
	if _, err := Deny(getenv, r.ID, "timo", now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	r6, ok, _ := Ask(getenv, "ship", "deploy", "prod/api", "agent", "t2", "", now.Add(4*time.Hour))
	if ok || r6.Status != "denied" {
		t.Fatalf("denied stays denied: %+v", r6)
	}
	if _, err := Approve(getenv, "nope", "timo", time.Hour, now); err == nil {
		t.Error("unknown id approved")
	}
}
