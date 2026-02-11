// Package cachesecurity provides ElastiCache and MemoryDB security analysis.
package cachesecurity

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticachetypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"
	memorydbtypes "github.com/aws/aws-sdk-go-v2/service/memorydb/types"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// CacheSecurityRisk represents ElastiCache / MemoryDB security misconfiguration.
type CacheSecurityRisk struct {
	Service        string
	RiskType       string
	Severity       string
	Resource       string
	Description    string
	Recommendation string
}

type service struct {
	elasticacheClient *elasticache.Client
	memorydbClient    *memorydb.Client
	ec2Client         *ec2.Client
}

// Service is the interface for cache security checks.
type Service interface {
	GetCacheSecurityRisks(ctx context.Context) ([]CacheSecurityRisk, error)
}

// NewService creates a new cache security service.
func NewService(cfg aws.Config) Service {
	return &service{
		elasticacheClient: elasticache.NewFromConfig(cfg),
		memorydbClient:    memorydb.NewFromConfig(cfg),
		ec2Client:         ec2.NewFromConfig(cfg),
	}
}

// GetCacheSecurityRisks checks ElastiCache and MemoryDB for common hardening gaps.
func (s *service) GetCacheSecurityRisks(ctx context.Context) ([]CacheSecurityRisk, error) {
	var risks []CacheSecurityRisk

	subnetPublicMap, err := s.getSubnetPublicMap(ctx)
	if err != nil {
		return nil, err
	}
	elasticacheSubnets, err := s.getElastiCacheSubnetGroups(ctx)
	if err != nil {
		return nil, err
	}
	memoryDBSubnets, err := s.getMemoryDBSubnetGroups(ctx)
	if err != nil {
		return nil, err
	}

	clusterPaginator := elasticache.NewDescribeCacheClustersPaginator(
		s.elasticacheClient,
		&elasticache.DescribeCacheClustersInput{ShowCacheNodeInfo: aws.Bool(true)},
	)
	for clusterPaginator.HasMorePages() {
		page, err := clusterPaginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, c := range page.CacheClusters {
			resource := aws.ToString(c.CacheClusterId)
			engine := strings.ToLower(aws.ToString(c.Engine))

			if encryptionDisabled(c.AtRestEncryptionEnabled) {
				risks = append(risks, newRisk(
					"ElastiCache",
					"NoEncryptionAtRest",
					SeverityHigh,
					resource,
					"Cache cluster does not have encryption at rest enabled",
					"Enable at-rest encryption using KMS for cache clusters",
				))
			}
			if encryptionDisabled(c.TransitEncryptionEnabled) {
				risks = append(risks, newRisk(
					"ElastiCache",
					"NoEncryptionInTransit",
					SeverityHigh,
					resource,
					"Cache cluster does not have encryption in transit enabled",
					"Enable transit encryption/TLS for cache traffic",
				))
			}
			if isRedisFamily(engine) && encryptionDisabled(c.AuthTokenEnabled) {
				risks = append(risks, newRisk(
					"ElastiCache",
					"NoRedisAuthToken",
					SeverityHigh,
					resource,
					"Redis/Valkey cache cluster does not enforce auth token",
					"Enable auth token and rotate credentials regularly",
				))
			}
			if isDefaultCachePort(aws.ToInt32(c.ConfigurationEndpoint.Port), engine) {
				risks = append(risks, newRisk(
					"ElastiCache",
					"DefaultPortUsed",
					SeverityLow,
					resource,
					"Cluster is using default cache service port",
					"Consider non-default ports combined with strict network access controls",
				))
			}
			subnetGroupName := aws.ToString(c.CacheSubnetGroupName)
			if subnetGroupIsPublic(subnetGroupName, elasticacheSubnets, subnetPublicMap) {
				risks = append(risks, newRisk(
					"ElastiCache",
					"PubliclyAccessiblePlacement",
					SeverityHigh,
					resource,
					"Cache subnet group includes subnet(s) configured for public IP assignment",
					"Use private subnets for cache subnet groups and enforce SG/NACL restrictions",
				))
			}
		}
	}

	rgPaginator := elasticache.NewDescribeReplicationGroupsPaginator(s.elasticacheClient, &elasticache.DescribeReplicationGroupsInput{})
	for rgPaginator.HasMorePages() {
		page, err := rgPaginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, rg := range page.ReplicationGroups {
			resource := aws.ToString(rg.ReplicationGroupId)
			engine := strings.ToLower(aws.ToString(rg.Engine))
			if encryptionDisabled(rg.AtRestEncryptionEnabled) {
				risks = append(risks, newRisk(
					"ElastiCache",
					"NoEncryptionAtRest",
					SeverityHigh,
					resource,
					"Replication group does not have encryption at rest enabled",
					"Enable at-rest encryption using KMS for replication groups",
				))
			}
			if encryptionDisabled(rg.TransitEncryptionEnabled) {
				risks = append(risks, newRisk(
					"ElastiCache",
					"NoEncryptionInTransit",
					SeverityHigh,
					resource,
					"Replication group does not have encryption in transit enabled",
					"Enable transit encryption/TLS for client and replication traffic",
				))
			}
			if isRedisFamily(engine) && encryptionDisabled(rg.AuthTokenEnabled) {
				risks = append(risks, newRisk(
					"ElastiCache",
					"NoRedisAuthToken",
					SeverityHigh,
					resource,
					"Redis/Valkey replication group does not enforce auth token",
					"Enable auth token and rotate credentials regularly",
				))
			}
		}
	}

	mdbPaginator := memorydb.NewDescribeClustersPaginator(s.memorydbClient, &memorydb.DescribeClustersInput{})
	for mdbPaginator.HasMorePages() {
		page, err := mdbPaginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, c := range page.Clusters {
			resource := aws.ToString(c.Name)
			if strings.TrimSpace(aws.ToString(c.KmsKeyId)) == "" {
				risks = append(risks, newRisk(
					"MemoryDB",
					"NoEncryptionAtRest",
					SeverityMedium,
					resource,
					"MemoryDB cluster has no customer-managed KMS key configured",
					"Configure a CMK to enforce explicit encryption key governance",
				))
			}
			if encryptionDisabled(c.TLSEnabled) {
				risks = append(risks, newRisk(
					"MemoryDB",
					"NoEncryptionInTransit",
					SeverityHigh,
					resource,
					"MemoryDB cluster does not have TLS enabled",
					"Enable TLS for in-transit encryption",
				))
			}
			if strings.EqualFold(aws.ToString(c.ACLName), "open-access") {
				risks = append(risks, newRisk(
					"MemoryDB",
					"NoRedisAuthToken",
					SeverityHigh,
					resource,
					"MemoryDB cluster is using open-access ACL",
					"Use a restrictive ACL with authenticated users and least privilege permissions",
				))
			}
			if isDefaultCachePort(resolveMemoryDBPort(c), "redis") {
				risks = append(risks, newRisk(
					"MemoryDB",
					"DefaultPortUsed",
					SeverityLow,
					resource,
					"Cluster is using default Redis port 6379",
					"Consider non-default ports combined with strict network access controls",
				))
			}
			subnetGroupName := aws.ToString(c.SubnetGroupName)
			if subnetGroupIsPublic(subnetGroupName, memoryDBSubnets, subnetPublicMap) {
				risks = append(risks, newRisk(
					"MemoryDB",
					"PubliclyAccessiblePlacement",
					SeverityHigh,
					resource,
					"MemoryDB subnet group includes subnet(s) configured for public IP assignment",
					"Use private subnets for MemoryDB subnet groups and enforce SG/NACL restrictions",
				))
			}
		}
	}

	return deduplicateRisks(risks), nil
}

func (s *service) getSubnetPublicMap(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	paginator := ec2.NewDescribeSubnetsPaginator(s.ec2Client, &ec2.DescribeSubnetsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe subnets: %w", err)
		}
		for _, subnet := range page.Subnets {
			out[aws.ToString(subnet.SubnetId)] = aws.ToBool(subnet.MapPublicIpOnLaunch)
		}
	}
	return out, nil
}

func (s *service) getElastiCacheSubnetGroups(ctx context.Context) (map[string][]string, error) {
	out := map[string][]string{}
	paginator := elasticache.NewDescribeCacheSubnetGroupsPaginator(s.elasticacheClient, &elasticache.DescribeCacheSubnetGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe cache subnet groups: %w", err)
		}
		for _, group := range page.CacheSubnetGroups {
			name := aws.ToString(group.CacheSubnetGroupName)
			for _, subnet := range group.Subnets {
				out[name] = append(out[name], aws.ToString(subnet.SubnetIdentifier))
			}
		}
	}
	return out, nil
}

func (s *service) getMemoryDBSubnetGroups(ctx context.Context) (map[string][]string, error) {
	out := map[string][]string{}
	paginator := memorydb.NewDescribeSubnetGroupsPaginator(s.memorydbClient, &memorydb.DescribeSubnetGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe memorydb subnet groups: %w", err)
		}
		for _, group := range page.SubnetGroups {
			name := aws.ToString(group.Name)
			for _, subnet := range group.Subnets {
				out[name] = append(out[name], aws.ToString(subnet.Identifier))
			}
		}
	}
	return out, nil
}

func resolveMemoryDBPort(cluster memorydbtypes.Cluster) int32 {
	if cluster.ClusterEndpoint != nil {
		return cluster.ClusterEndpoint.Port
	}
	return 0
}

func subnetGroupIsPublic(groupName string, groupSubnets map[string][]string, subnetPublicMap map[string]bool) bool {
	if strings.TrimSpace(groupName) == "" {
		return false
	}
	subnets := groupSubnets[groupName]
	for _, subnetID := range subnets {
		if subnetPublicMap[subnetID] {
			return true
		}
	}
	return false
}

func isRedisFamily(engine string) bool {
	engine = strings.ToLower(strings.TrimSpace(engine))
	return engine == "redis" || engine == "valkey"
}

func encryptionDisabled(v *bool) bool {
	return v != nil && !aws.ToBool(v)
}

func isDefaultCachePort(port int32, engine string) bool {
	switch strings.ToLower(strings.TrimSpace(engine)) {
	case "redis", "valkey":
		return port == 6379
	case "memcached":
		return port == 11211
	default:
		return false
	}
}

func newRisk(serviceName, riskType, severity, resource, description, recommendation string) CacheSecurityRisk {
	return CacheSecurityRisk{
		Service:        serviceName,
		RiskType:       riskType,
		Severity:       severity,
		Resource:       resource,
		Description:    description,
		Recommendation: recommendation,
	}
}

func deduplicateRisks(in []CacheSecurityRisk) []CacheSecurityRisk {
	seen := map[string]bool{}
	out := make([]CacheSecurityRisk, 0, len(in))
	for _, r := range in {
		key := fmt.Sprintf("%s|%s|%s", r.Service, r.RiskType, r.Resource)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}

// compile-time assertions when SDK structs change.
var (
	_ = elasticachetypes.CacheCluster{}
)
