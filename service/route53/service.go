// Package route53 provides Route53 DNS security analysis.
package route53

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// HostedZoneRisk represents a security issue with a hosted zone
type HostedZoneRisk struct {
	HostedZoneID   string
	HostedZoneName string
	RiskType       string
	Severity       string
	Description    string
	Recommendation string
}

// DNSSECStatus represents DNSSEC configuration status
type DNSSECStatus struct {
	HostedZoneID   string
	HostedZoneName string
	DNSSECEnabled  bool
	Status         string
	Severity       string
	Recommendation string
}

// DanglingDNSRecord represents a potential dangling DNS record
type DanglingDNSRecord struct {
	HostedZoneName string
	RecordName     string
	RecordType     string
	Value          string
	Severity       string
	Description    string
	Recommendation string
}

type service struct {
	client *route53.Client
}

// Service is the interface for Route53 security analysis
type Service interface {
	GetHostedZoneRisks(ctx context.Context) ([]HostedZoneRisk, error)
	GetDNSSECStatus(ctx context.Context) ([]DNSSECStatus, error)
	GetDanglingRecords(ctx context.Context) ([]DanglingDNSRecord, error)
}

// NewService creates a new Route53 service
func NewService(cfg aws.Config) Service {
	return &service{
		client: route53.NewFromConfig(cfg),
	}
}

// GetHostedZoneRisks analyzes hosted zones for security issues
func (s *service) GetHostedZoneRisks(ctx context.Context) ([]HostedZoneRisk, error) {
	var risks []HostedZoneRisk

	zones, err := s.client.ListHostedZones(ctx, &route53.ListHostedZonesInput{})
	if err != nil {
		return nil, err
	}

	for _, zone := range zones.HostedZones {
		zoneID := extractZoneID(aws.ToString(zone.Id))

		// Check query logging
		logging, _ := s.client.ListQueryLoggingConfigs(ctx, &route53.ListQueryLoggingConfigsInput{
			HostedZoneId: aws.String(zoneID),
		})

		if logging == nil || len(logging.QueryLoggingConfigs) == 0 {
			risks = append(risks, HostedZoneRisk{
				HostedZoneID:   zoneID,
				HostedZoneName: aws.ToString(zone.Name),
				RiskType:       "NO_QUERY_LOGGING",
				Severity:       SeverityMedium,
				Description:    "DNS query logging not enabled",
				Recommendation: "Enable query logging to CloudWatch for visibility into DNS queries",
			})
		}

		// Check if public zone (not private)
		if !zone.Config.PrivateZone {
			// Public zones should have DNSSEC
			dnssec, _ := s.client.GetDNSSEC(ctx, &route53.GetDNSSECInput{
				HostedZoneId: aws.String(zoneID),
			})

			if dnssec == nil || dnssec.Status == nil || dnssec.Status.ServeSignature == nil || *dnssec.Status.ServeSignature != "SIGNING" {
				risks = append(risks, HostedZoneRisk{
					HostedZoneID:   zoneID,
					HostedZoneName: aws.ToString(zone.Name),
					RiskType:       "NO_DNSSEC",
					Severity:       SeverityMedium,
					Description:    "Public zone without DNSSEC - vulnerable to DNS spoofing",
					Recommendation: "Enable DNSSEC for domain integrity protection",
				})
			}
		}
	}

	return risks, nil
}

// GetDNSSECStatus checks DNSSEC configuration for all hosted zones
func (s *service) GetDNSSECStatus(ctx context.Context) ([]DNSSECStatus, error) {
	var statuses []DNSSECStatus

	zones, err := s.client.ListHostedZones(ctx, &route53.ListHostedZonesInput{})
	if err != nil {
		return nil, err
	}

	for _, zone := range zones.HostedZones {
		// Skip private zones (DNSSEC only applies to public)
		if zone.Config.PrivateZone {
			continue
		}

		zoneID := extractZoneID(aws.ToString(zone.Id))

		dnssec, err := s.client.GetDNSSEC(ctx, &route53.GetDNSSECInput{
			HostedZoneId: aws.String(zoneID),
		})

		status := DNSSECStatus{
			HostedZoneID:   zoneID,
			HostedZoneName: aws.ToString(zone.Name),
		}

		if err != nil || dnssec.Status == nil || dnssec.Status.ServeSignature == nil || *dnssec.Status.ServeSignature != "SIGNING" {
			status.DNSSECEnabled = false
			status.Status = "DISABLED"
			status.Severity = SeverityMedium
			status.Recommendation = "Enable DNSSEC to protect against DNS cache poisoning"
		} else {
			status.DNSSECEnabled = true
			status.Status = "ENABLED"
			status.Severity = SeverityInfo
			status.Recommendation = "DNSSEC is properly configured"
		}

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// GetDanglingRecords finds DNS records that may point to non-existent resources
func (s *service) GetDanglingRecords(ctx context.Context) ([]DanglingDNSRecord, error) {
	var dangling []DanglingDNSRecord

	zones, err := s.client.ListHostedZones(ctx, &route53.ListHostedZonesInput{})
	if err != nil {
		return nil, err
	}

	for _, zone := range zones.HostedZones {
		zoneID := extractZoneID(aws.ToString(zone.Id))

		records, err := s.client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
			HostedZoneId: aws.String(zoneID),
		})
		if err != nil {
			continue
		}

		for _, record := range records.ResourceRecordSets {
			recordType := string(record.Type)

			// Check CNAME records for potential dangling references
			if recordType == "CNAME" {
				for _, rr := range record.ResourceRecords {
					value := aws.ToString(rr.Value)

					// Check for common cloud provider patterns that might be dangling
					if isDanglingCandidate(value) {
						dangling = append(dangling, DanglingDNSRecord{
							HostedZoneName: aws.ToString(zone.Name),
							RecordName:     aws.ToString(record.Name),
							RecordType:     recordType,
							Value:          value,
							Severity:       SeverityHigh,
							Description:    "CNAME points to cloud resource - verify ownership to prevent subdomain takeover",
							Recommendation: "Verify the target resource exists and is under your control",
						})
					}
				}
			}
		}
	}

	return dangling, nil
}

func extractZoneID(id string) string {
	// Remove /hostedzone/ prefix if present
	return strings.TrimPrefix(id, "/hostedzone/")
}

func isDanglingCandidate(value string) bool {
	// Patterns that may indicate dangling DNS (subdomain takeover risk)
	patterns := []string{
		".s3.amazonaws.com",
		".s3-website",
		".cloudfront.net",
		".elasticbeanstalk.com",
		".herokuapp.com",
		".azurewebsites.net",
		".trafficmanager.net",
		".github.io",
		".netlify.app",
		".vercel.app",
	}

	for _, pattern := range patterns {
		if strings.Contains(strings.ToLower(value), pattern) {
			return true
		}
	}

	return false
}
