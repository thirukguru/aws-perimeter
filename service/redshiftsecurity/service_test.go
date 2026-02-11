package redshiftsecurity

import "testing"

func TestBoolHelpers(t *testing.T) {
	vTrue := true
	vFalse := false
	if !boolTrue(&vTrue) {
		t.Fatalf("expected true pointer to be true")
	}
	if boolTrue(&vFalse) {
		t.Fatalf("expected false pointer to be false")
	}
	if !boolFalse(&vFalse) {
		t.Fatalf("expected false pointer to be false helper true")
	}
	if boolFalse(&vTrue) {
		t.Fatalf("expected true pointer to be false helper false")
	}
}

func TestDedupeRisks(t *testing.T) {
	in := []RedshiftRisk{
		{RiskType: "AuditLoggingDisabled", Resource: "cluster-a"},
		{RiskType: "AuditLoggingDisabled", Resource: "cluster-a"},
		{RiskType: "EnhancedVPCRoutingDisabled", Resource: "cluster-a"},
	}
	out := dedupeRisks(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 unique risks, got %d", len(out))
	}
}
