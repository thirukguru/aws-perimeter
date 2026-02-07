package vpc

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Risky ports that should never be open to the internet.
var riskyPorts = map[int32]string{
	22:    "SSH",
	3389:  "RDP",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	1433:  "MSSQL",
	1521:  "Oracle",
	27017: "MongoDB",
	6379:  "Redis",
	9200:  "Elasticsearch",
	5601:  "Kibana",
	2379:  "etcd",
	8080:  "HTTP-Alt",
	23:    "Telnet",
	21:    "FTP",
	445:   "SMB",
	135:   "RPC",
	161:   "SNMP",
	162:   "SNMP-Trap",
}

// managementPorts are admin interfaces commonly targeted by nation-state actors.
// Reference: AWS Threat Intel - GRU Sandworm campaign (Dec 2025)
var managementPorts = map[int32]bool{
	22:   true, // SSH
	3389: true, // RDP
	443:  true, // HTTPS admin panels
	8443: true, // Alt HTTPS admin
	8080: true, // HTTP admin
	9090: true, // Cockpit/admin
}

// plaintextPorts allow credential interception via packet capture.
// Reference: AWS Threat Intel - credential harvesting via traffic interception
var plaintextPorts = map[int32]string{
	23:  "Telnet",
	21:  "FTP",
	80:  "HTTP",
	161: "SNMP",
	162: "SNMP-Trap",
	25:  "SMTP",
	110: "POP3",
	143: "IMAP",
}

func (s *service) GetSecurityGroupRisks(ctx context.Context) ([]SGRisk, error) {
	var risks []SGRisk

	paginator := ec2.NewDescribeSecurityGroupsPaginator(s.client, &ec2.DescribeSecurityGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe security groups: %w", err)
		}

		for _, sg := range page.SecurityGroups {
			sgRisks := s.analyzeSecurityGroup(sg)
			risks = append(risks, sgRisks...)
		}
	}

	return risks, nil
}

func (s *service) analyzeSecurityGroup(sg types.SecurityGroup) []SGRisk {
	var risks []SGRisk
	sgID := aws.ToString(sg.GroupId)
	sgName := aws.ToString(sg.GroupName)
	vpcID := aws.ToString(sg.VpcId)

	for _, rule := range sg.IpPermissions {
		for _, ipRange := range rule.IpRanges {
			cidr := aws.ToString(ipRange.CidrIp)

			// Check if open to the world
			if cidr != "0.0.0.0/0" {
				continue
			}

			fromPort := int32(0)
			toPort := int32(65535)

			if rule.FromPort != nil {
				fromPort = *rule.FromPort
			}

			if rule.ToPort != nil {
				toPort = *rule.ToPort
			}

			// Check for risky ports
			for port, portName := range riskyPorts {
				if fromPort <= port && port <= toPort {
					severity := SeverityCritical
					if port == 8080 {
						severity = SeverityMedium
					}

					risks = append(risks, SGRisk{
						SecurityGroupID:   sgID,
						SecurityGroupName: sgName,
						VpcID:             vpcID,
						RiskType:          fmt.Sprintf("OPEN_%s", strings.ToUpper(portName)),
						Severity:          severity,
						Port:              port,
						Protocol:          aws.ToString(rule.IpProtocol),
						SourceCIDR:        cidr,
						Description:       fmt.Sprintf("%s (port %d) is open to the internet (0.0.0.0/0)", portName, port),
						Recommendation:    fmt.Sprintf("Restrict %s access to specific IP ranges or use a bastion host/VPN", portName),
					})
				}
			}

			// Check for all ports open
			if fromPort == 0 && toPort == 65535 {
				risks = append(risks, SGRisk{
					SecurityGroupID:   sgID,
					SecurityGroupName: sgName,
					VpcID:             vpcID,
					RiskType:          "ALL_PORTS_OPEN",
					Severity:          SeverityCritical,
					Port:              -1,
					Protocol:          aws.ToString(rule.IpProtocol),
					SourceCIDR:        cidr,
					Description:       "All ports (0-65535) are open to the internet",
					Recommendation:    "Restrict to only required ports and specific IP ranges",
				})
			}
		}

		// Check IPv6 ranges
		for _, ipv6Range := range rule.Ipv6Ranges {
			cidr := aws.ToString(ipv6Range.CidrIpv6)
			if cidr == "::/0" {
				fromPort := int32(0)
				toPort := int32(65535)

				if rule.FromPort != nil {
					fromPort = *rule.FromPort
				}

				if rule.ToPort != nil {
					toPort = *rule.ToPort
				}

				for port, portName := range riskyPorts {
					if fromPort <= port && port <= toPort {
						risks = append(risks, SGRisk{
							SecurityGroupID:   sgID,
							SecurityGroupName: sgName,
							VpcID:             vpcID,
							RiskType:          fmt.Sprintf("OPEN_%s_IPV6", strings.ToUpper(portName)),
							Severity:          SeverityCritical,
							Port:              port,
							Protocol:          aws.ToString(rule.IpProtocol),
							SourceCIDR:        cidr,
							Description:       fmt.Sprintf("%s (port %d) is open to the internet via IPv6 (::/0)", portName, port),
							Recommendation:    fmt.Sprintf("Restrict %s access to specific IP ranges", portName),
						})
					}
				}
			}
		}
	}

	return risks
}

func (s *service) GetUnusedSecurityGroups(ctx context.Context) ([]UnusedSG, error) {
	var unused []UnusedSG

	// Get all security groups
	allSGs := make(map[string]types.SecurityGroup)

	sgPaginator := ec2.NewDescribeSecurityGroupsPaginator(s.client, &ec2.DescribeSecurityGroupsInput{})
	for sgPaginator.HasMorePages() {
		page, err := sgPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe security groups: %w", err)
		}

		for _, sg := range page.SecurityGroups {
			// Skip default security groups
			if aws.ToString(sg.GroupName) == "default" {
				continue
			}

			allSGs[aws.ToString(sg.GroupId)] = sg
		}
	}

	// Get security groups in use by network interfaces
	usedSGs := make(map[string]bool)

	eniPaginator := ec2.NewDescribeNetworkInterfacesPaginator(s.client, &ec2.DescribeNetworkInterfacesInput{})
	for eniPaginator.HasMorePages() {
		page, err := eniPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe network interfaces: %w", err)
		}

		for _, eni := range page.NetworkInterfaces {
			for _, group := range eni.Groups {
				usedSGs[aws.ToString(group.GroupId)] = true
			}
		}
	}

	// Find unused security groups
	for sgID, sg := range allSGs {
		if !usedSGs[sgID] {
			unused = append(unused, UnusedSG{
				SecurityGroupID:   sgID,
				SecurityGroupName: aws.ToString(sg.GroupName),
				VpcID:             aws.ToString(sg.VpcId),
				Description:       aws.ToString(sg.Description),
			})
		}
	}

	return unused, nil
}

func (s *service) GetPublicExposureRisks(ctx context.Context) ([]ExposureRisk, error) {
	var risks []ExposureRisk

	// Build a map of security group risks
	sgRisks, err := s.GetSecurityGroupRisks(ctx)
	if err != nil {
		return nil, err
	}

	riskySGs := make(map[string][]SGRisk)
	for _, risk := range sgRisks {
		riskySGs[risk.SecurityGroupID] = append(riskySGs[risk.SecurityGroupID], risk)
	}

	// Find instances with public IPs and risky security groups
	instancePaginator := ec2.NewDescribeInstancesPaginator(s.client, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	})

	for instancePaginator.HasMorePages() {
		page, err := instancePaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe instances: %w", err)
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				publicIP := aws.ToString(instance.PublicIpAddress)
				if publicIP == "" {
					continue
				}

				var instanceSGIDs []string
				var openPorts []int32
				hasRisk := false

				for _, sg := range instance.SecurityGroups {
					sgID := aws.ToString(sg.GroupId)
					instanceSGIDs = append(instanceSGIDs, sgID)

					if risks, ok := riskySGs[sgID]; ok {
						hasRisk = true
						for _, r := range risks {
							if r.Port > 0 {
								openPorts = append(openPorts, r.Port)
							}
						}
					}
				}

				if hasRisk {
					instanceName := ""
					for _, tag := range instance.Tags {
						if aws.ToString(tag.Key) == "Name" {
							instanceName = aws.ToString(tag.Value)

							break
						}
					}

					risks = append(risks, ExposureRisk{
						InstanceID:       aws.ToString(instance.InstanceId),
						InstanceName:     instanceName,
						PublicIP:         publicIP,
						SecurityGroupIDs: instanceSGIDs,
						OpenPorts:        openPorts,
						Severity:         SeverityCritical,
						Description:      fmt.Sprintf("Instance %s has public IP %s with risky open ports", aws.ToString(instance.InstanceId), publicIP),
						Recommendation:   "Review security groups and restrict access to necessary ports and IP ranges",
					})
				}
			}
		}
	}

	return risks, nil
}

func (s *service) GetNACLRisks(ctx context.Context) ([]NACLRisk, error) {
	var risks []NACLRisk

	output, err := s.client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe network ACLs: %w", err)
	}

	for _, nacl := range output.NetworkAcls {
		naclID := aws.ToString(nacl.NetworkAclId)
		vpcID := aws.ToString(nacl.VpcId)

		var subnetIDs []string
		for _, assoc := range nacl.Associations {
			subnetIDs = append(subnetIDs, aws.ToString(assoc.SubnetId))
		}

		for _, entry := range nacl.Entries {
			// Skip deny rules and egress rules (focus on inbound allow)
			if entry.Egress != nil && *entry.Egress {
				continue
			}

			if entry.RuleAction != types.RuleActionAllow {
				continue
			}

			cidr := aws.ToString(entry.CidrBlock)
			if cidr != "0.0.0.0/0" {
				continue
			}

			// Check if all traffic or risky ports are allowed
			protocol := aws.ToString(entry.Protocol)
			if protocol == "-1" { // All traffic
				risks = append(risks, NACLRisk{
					NetworkAclID: naclID,
					VpcID:        vpcID,
					SubnetIDs:    subnetIDs,
					RuleNumber:   aws.ToInt32(entry.RuleNumber),
					IsEgress:     false,
					Protocol:     "ALL",
					PortRange:    "ALL",
					CidrBlock:    cidr,
					RuleAction:   "ALLOW",
					Severity:     SeverityMedium,
					Description:  "NACL allows all inbound traffic from 0.0.0.0/0",
				})
			}
		}
	}

	return risks, nil
}

func (s *service) GetVPCFlowLogStatus(ctx context.Context) ([]FlowLogStatus, error) {
	var results []FlowLogStatus

	// Get all VPCs
	vpcsOutput, err := s.client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPCs: %w", err)
	}

	// Get all flow logs
	flowLogsOutput, err := s.client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe flow logs: %w", err)
	}

	// Map VPC IDs to their flow logs
	vpcFlowLogs := make(map[string][]string)
	for _, fl := range flowLogsOutput.FlowLogs {
		if fl.ResourceId != nil {
			vpcFlowLogs[*fl.ResourceId] = append(vpcFlowLogs[*fl.ResourceId], aws.ToString(fl.FlowLogId))
		}
	}

	for _, vpc := range vpcsOutput.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		vpcName := ""

		for _, tag := range vpc.Tags {
			if aws.ToString(tag.Key) == "Name" {
				vpcName = aws.ToString(tag.Value)

				break
			}
		}

		flowLogIDs := vpcFlowLogs[vpcID]
		enabled := len(flowLogIDs) > 0

		status := FlowLogStatus{
			VpcID:           vpcID,
			VpcName:         vpcName,
			FlowLogsEnabled: enabled,
			FlowLogIDs:      flowLogIDs,
		}

		if !enabled {
			status.Severity = SeverityMedium
			status.Recommendation = "Enable VPC Flow Logs for network traffic visibility and security monitoring"
		} else {
			status.Severity = SeverityInfo
		}

		results = append(results, status)
	}

	return results, nil
}

// GetManagementExposureRisks finds EC2 instances with management ports exposed to the internet.
// Reference: AWS Threat Intel - GRU Sandworm campaign targeting misconfigured network edge devices.
func (s *service) GetManagementExposureRisks(ctx context.Context) ([]ManagementExposure, error) {
	var risks []ManagementExposure

	// Get all security groups and their open management ports
	sgMgmtPorts := make(map[string][]int32)

	paginator := ec2.NewDescribeSecurityGroupsPaginator(s.client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe security groups: %w", err)
		}

		for _, sg := range page.SecurityGroups {
			sgID := aws.ToString(sg.GroupId)
			for _, rule := range sg.IpPermissions {
				for _, ipRange := range rule.IpRanges {
					if aws.ToString(ipRange.CidrIp) != "0.0.0.0/0" {
						continue
					}

					fromPort := int32(0)
					toPort := int32(65535)
					if rule.FromPort != nil {
						fromPort = *rule.FromPort
					}
					if rule.ToPort != nil {
						toPort = *rule.ToPort
					}

					for port := range managementPorts {
						if fromPort <= port && port <= toPort {
							sgMgmtPorts[sgID] = append(sgMgmtPorts[sgID], port)
						}
					}
				}
			}
		}
	}

	// Find instances with public IPs and exposed management ports
	instancePaginator := ec2.NewDescribeInstancesPaginator(s.client, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{Name: aws.String("instance-state-name"), Values: []string{"running"}},
		},
	})

	for instancePaginator.HasMorePages() {
		page, err := instancePaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe instances: %w", err)
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				publicIP := aws.ToString(instance.PublicIpAddress)
				if publicIP == "" {
					continue
				}

				var exposedPorts []int32
				var sgIDs []string

				for _, sg := range instance.SecurityGroups {
					sgID := aws.ToString(sg.GroupId)
					sgIDs = append(sgIDs, sgID)
					if ports, ok := sgMgmtPorts[sgID]; ok {
						exposedPorts = append(exposedPorts, ports...)
					}
				}

				if len(exposedPorts) > 0 {
					instanceName := aws.ToString(instance.InstanceId)
					for _, tag := range instance.Tags {
						if aws.ToString(tag.Key) == "Name" {
							instanceName = aws.ToString(tag.Value)
							break
						}
					}

					risks = append(risks, ManagementExposure{
						InstanceID:     aws.ToString(instance.InstanceId),
						InstanceName:   instanceName,
						PublicIP:       publicIP,
						ExposedPorts:   exposedPorts,
						SecurityGroups: sgIDs,
						Severity:       SeverityCritical,
						Description:    fmt.Sprintf("Management interface exposed to internet on ports %v (nation-state attack vector)", exposedPorts),
						Recommendation: "Move management interfaces to private subnets, use bastion hosts or VPN",
					})
				}
			}
		}
	}

	return risks, nil
}

// GetPlaintextProtocolRisks finds security groups allowing unencrypted protocols.
// Reference: AWS Threat Intel - credential harvesting via traffic interception.
func (s *service) GetPlaintextProtocolRisks(ctx context.Context) ([]PlaintextRisk, error) {
	var risks []PlaintextRisk

	paginator := ec2.NewDescribeSecurityGroupsPaginator(s.client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe security groups: %w", err)
		}

		for _, sg := range page.SecurityGroups {
			sgID := aws.ToString(sg.GroupId)
			sgName := aws.ToString(sg.GroupName)
			vpcID := aws.ToString(sg.VpcId)

			for _, rule := range sg.IpPermissions {
				for _, ipRange := range rule.IpRanges {
					cidr := aws.ToString(ipRange.CidrIp)
					if cidr != "0.0.0.0/0" {
						continue
					}

					fromPort := int32(0)
					toPort := int32(65535)
					if rule.FromPort != nil {
						fromPort = *rule.FromPort
					}
					if rule.ToPort != nil {
						toPort = *rule.ToPort
					}

					for port, protocol := range plaintextPorts {
						if fromPort <= port && port <= toPort {
							risks = append(risks, PlaintextRisk{
								SecurityGroupID:   sgID,
								SecurityGroupName: sgName,
								VpcID:             vpcID,
								Protocol:          protocol,
								Port:              port,
								SourceCIDR:        cidr,
								Severity:          SeverityCritical,
								Description:       fmt.Sprintf("Plaintext %s (port %d) exposed - credentials can be intercepted", protocol, port),
								Recommendation:    fmt.Sprintf("Disable %s and use encrypted alternatives (SSH, HTTPS, TLS)", protocol),
							})
						}
					}
				}
			}
		}
	}

	return risks, nil
}

// GetIMDSv1Risks finds EC2 instances with IMDSv1 enabled (credential theft risk).
// Reference: AWS Threat Intel - IMDSv1 enables easier credential theft.
func (s *service) GetIMDSv1Risks(ctx context.Context) ([]IMDSv1Risk, error) {
	var risks []IMDSv1Risk

	paginator := ec2.NewDescribeInstancesPaginator(s.client, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{Name: aws.String("instance-state-name"), Values: []string{"running"}},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe instances: %w", err)
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				// Check if IMDSv1 is enabled (HttpTokens != "required")
				if instance.MetadataOptions == nil {
					continue
				}

				// IMDSv2 is enforced when HttpTokens == "required"
				// IMDSv1 is allowed when HttpTokens == "optional"
				if instance.MetadataOptions.HttpTokens == types.HttpTokensStateOptional {
					instanceName := aws.ToString(instance.InstanceId)
					for _, tag := range instance.Tags {
						if aws.ToString(tag.Key) == "Name" {
							instanceName = aws.ToString(tag.Value)
							break
						}
					}

					risks = append(risks, IMDSv1Risk{
						InstanceID:     aws.ToString(instance.InstanceId),
						InstanceName:   instanceName,
						IMDSv1Enabled:  true,
						Severity:       SeverityHigh,
						Description:    "IMDSv1 enabled - instance metadata vulnerable to SSRF credential theft",
						Recommendation: "Enforce IMDSv2 by setting HttpTokens to 'required'",
					})
				}
			}
		}
	}

	return risks, nil
}

// VPN/Firewall AMI patterns for network appliance detection
var networkAppliancePatterns = []struct {
	Pattern       string
	ApplianceType string
}{
	{"cisco", "Router/Firewall"},
	{"paloalto", "Firewall"},
	{"fortinet", "Firewall"},
	{"fortigate", "Firewall"},
	{"sophos", "Firewall"},
	{"checkpoint", "Firewall"},
	{"barracuda", "Firewall"},
	{"openvpn", "VPN"},
	{"wireguard", "VPN"},
	{"pritunl", "VPN"},
	{"vyos", "Router"},
	{"pfsense", "Firewall"},
	{"openswan", "VPN"},
	{"strongswan", "VPN"},
	{"netgate", "Firewall"},
	{"nat-gateway", "NAT"},
	{"nat-instance", "NAT"},
}

// GetNetworkApplianceRisks finds EC2 instances running VPN/firewall appliances
// Based on GRU Sandworm campaign targeting network edge devices
func (s *service) GetNetworkApplianceRisks(ctx context.Context) ([]NetworkAppliance, error) {
	var risks []NetworkAppliance

	paginator := ec2.NewDescribeInstancesPaginator(s.client, &ec2.DescribeInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe instances: %w", err)
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				if instance.State == nil || instance.State.Name != types.InstanceStateNameRunning {
					continue
				}

				instanceName := getInstanceName(instance.Tags)
				amiID := aws.ToString(instance.ImageId)
				nameLower := strings.ToLower(instanceName)

				// Check instance name and AMI for appliance patterns
				for _, pattern := range networkAppliancePatterns {
					patternLower := strings.ToLower(pattern.Pattern)

					if strings.Contains(nameLower, patternLower) ||
						strings.Contains(strings.ToLower(amiID), patternLower) {

						isPublic := instance.PublicIpAddress != nil
						severity := SeverityMedium
						if isPublic {
							severity = SeverityHigh
						}

						risks = append(risks, NetworkAppliance{
							InstanceID:       aws.ToString(instance.InstanceId),
							InstanceName:     instanceName,
							AMIID:            amiID,
							ApplianceType:    pattern.ApplianceType,
							PublicIP:         aws.ToString(instance.PublicIpAddress),
							IsInternetFacing: isPublic,
							Severity:         severity,
							Description:      fmt.Sprintf("Network appliance detected (%s) - priority target for nation-state actors", pattern.ApplianceType),
							Recommendation:   "Ensure firmware is up-to-date, restrict management access, enable logging",
						})
						break
					}
				}
			}
		}
	}

	return risks, nil
}

// Management ports that should not be in public subnets
var mgmtPorts = []int32{22, 3389, 443, 8443, 8080, 9090, 5900, 5901}

// GetManagementSubnetRisks finds instances with management interfaces in public subnets
func (s *service) GetManagementSubnetRisks(ctx context.Context) ([]ManagementSubnetRisk, error) {
	var risks []ManagementSubnetRisk

	// Get all instances with public IPs
	paginator := ec2.NewDescribeInstancesPaginator(s.client, &ec2.DescribeInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe instances: %w", err)
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				if instance.State == nil || instance.State.Name != types.InstanceStateNameRunning {
					continue
				}

				// Only check instances with public IPs (in public subnets)
				if instance.PublicIpAddress == nil {
					continue
				}

				instanceName := getInstanceName(instance.Tags)

				// Check security groups for exposed management ports
				var exposedPorts []int32
				for _, sg := range instance.SecurityGroups {
					sgID := aws.ToString(sg.GroupId)
					exposedMgmt := s.getExposedMgmtPorts(ctx, sgID)
					exposedPorts = append(exposedPorts, exposedMgmt...)
				}

				if len(exposedPorts) > 0 {
					risks = append(risks, ManagementSubnetRisk{
						InstanceID:       aws.ToString(instance.InstanceId),
						InstanceName:     instanceName,
						SubnetID:         aws.ToString(instance.SubnetId),
						SubnetType:       "PUBLIC",
						ExposedMgmtPorts: uniquePorts(exposedPorts),
						PublicIP:         aws.ToString(instance.PublicIpAddress),
						Severity:         SeverityMedium,
						Description:      "Instance with management ports in public subnet - move to private subnet",
						Recommendation:   "Use VPN/bastion for management access, move to private subnet",
					})
				}
			}
		}
	}

	return risks, nil
}

func (s *service) getExposedMgmtPorts(ctx context.Context, sgID string) []int32 {
	var exposed []int32

	sg, err := s.client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	})
	if err != nil || len(sg.SecurityGroups) == 0 {
		return exposed
	}

	for _, rule := range sg.SecurityGroups[0].IpPermissions {
		// Check if open to internet
		for _, ipRange := range rule.IpRanges {
			if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
				fromPort := aws.ToInt32(rule.FromPort)
				toPort := aws.ToInt32(rule.ToPort)

				for _, mgmtPort := range mgmtPorts {
					if mgmtPort >= fromPort && mgmtPort <= toPort {
						exposed = append(exposed, mgmtPort)
					}
				}
			}
		}
	}

	return exposed
}

func getInstanceName(tags []types.Tag) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == "Name" {
			return aws.ToString(tag.Value)
		}
	}
	return ""
}

func uniquePorts(ports []int32) []int32 {
	seen := make(map[int32]bool)
	var result []int32
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}
