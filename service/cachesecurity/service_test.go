package cachesecurity

import "testing"

func TestIsRedisFamily(t *testing.T) {
	if !isRedisFamily("redis") {
		t.Fatalf("expected redis to be redis family")
	}
	if !isRedisFamily("valkey") {
		t.Fatalf("expected valkey to be redis family")
	}
	if isRedisFamily("memcached") {
		t.Fatalf("did not expect memcached to be redis family")
	}
}

func TestIsDefaultCachePort(t *testing.T) {
	if !isDefaultCachePort(6379, "redis") {
		t.Fatalf("expected redis default port to match")
	}
	if !isDefaultCachePort(11211, "memcached") {
		t.Fatalf("expected memcached default port to match")
	}
	if isDefaultCachePort(6380, "redis") {
		t.Fatalf("did not expect non-default redis port")
	}
}

func TestSubnetGroupIsPublic(t *testing.T) {
	groupSubnets := map[string][]string{
		"cache-a": {"subnet-1", "subnet-2"},
	}
	subnetPublicMap := map[string]bool{
		"subnet-1": false,
		"subnet-2": true,
	}
	if !subnetGroupIsPublic("cache-a", groupSubnets, subnetPublicMap) {
		t.Fatalf("expected cache-a to be public")
	}
	if subnetGroupIsPublic("cache-b", groupSubnets, subnetPublicMap) {
		t.Fatalf("did not expect unknown group to be public")
	}
}

func TestDeduplicateRisks(t *testing.T) {
	in := []CacheSecurityRisk{
		{Service: "ElastiCache", RiskType: "NoEncryptionAtRest", Resource: "c1"},
		{Service: "ElastiCache", RiskType: "NoEncryptionAtRest", Resource: "c1"},
		{Service: "ElastiCache", RiskType: "NoEncryptionInTransit", Resource: "c1"},
	}
	out := deduplicateRisks(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 unique risks, got %d", len(out))
	}
}
