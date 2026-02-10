// Package orchestrator coordinates the execution of security checks.
package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/thirukguru/aws-perimeter/model"
	"github.com/thirukguru/aws-perimeter/service/aidetection"
	"github.com/thirukguru/aws-perimeter/service/apigateway"
	"github.com/thirukguru/aws-perimeter/service/cloudtrail"
	"github.com/thirukguru/aws-perimeter/service/cloudtrailsecurity"
	"github.com/thirukguru/aws-perimeter/service/config"
	"github.com/thirukguru/aws-perimeter/service/dataprotection"
	"github.com/thirukguru/aws-perimeter/service/ecssecurity"
	"github.com/thirukguru/aws-perimeter/service/ekssecurity"
	"github.com/thirukguru/aws-perimeter/service/elb"
	"github.com/thirukguru/aws-perimeter/service/governance"
	"github.com/thirukguru/aws-perimeter/service/guardduty"
	"github.com/thirukguru/aws-perimeter/service/iam"
	"github.com/thirukguru/aws-perimeter/service/iamadvanced"
	"github.com/thirukguru/aws-perimeter/service/inspector"
	"github.com/thirukguru/aws-perimeter/service/lambdasecurity"
	"github.com/thirukguru/aws-perimeter/service/logging"
	"github.com/thirukguru/aws-perimeter/service/messaging"
	"github.com/thirukguru/aws-perimeter/service/output"
	"github.com/thirukguru/aws-perimeter/service/resourcepolicy"
	"github.com/thirukguru/aws-perimeter/service/route53"
	"github.com/thirukguru/aws-perimeter/service/s3security"
	"github.com/thirukguru/aws-perimeter/service/secrets"
	"github.com/thirukguru/aws-perimeter/service/securityhub"
	"github.com/thirukguru/aws-perimeter/service/shield"
	"github.com/thirukguru/aws-perimeter/service/storage"
	awssts "github.com/thirukguru/aws-perimeter/service/sts"
	"github.com/thirukguru/aws-perimeter/service/vpc"
	"github.com/thirukguru/aws-perimeter/service/vpcadvanced"
	"github.com/thirukguru/aws-perimeter/service/vpcendpoints"
	extratables "github.com/thirukguru/aws-perimeter/shared/extra_tables"
	htmloutput "github.com/thirukguru/aws-perimeter/shared/html_output"
	"golang.org/x/sync/errgroup"
)

// NewService creates a new orchestrator service.
func NewService(
	stsService awssts.Service,
	vpcService vpc.Service,
	iamService iam.Service,
	s3Service s3security.Service,
	cloudtrailService cloudtrail.Service,
	secretsService secrets.Service,
	securityhubSvc securityhub.Service,
	guarddutyService guardduty.Service,
	apigatewayService apigateway.Service,
	resourcePolSvc resourcepolicy.Service,
	outputService output.Service,
	versionInfo model.VersionInfo,
	// Extended services
	shieldService shield.Service,
	elbService elb.Service,
	route53Service route53.Service,
	inspectorService inspector.Service,
	lambdaSecService lambdasecurity.Service,
	messagingService messaging.Service,
	cloudtrailSecService cloudtrailsecurity.Service,
	configService config.Service,
	dataprotectionSvc dataprotection.Service,
	loggingService logging.Service,
	governanceService governance.Service,
	vpcEndpointsService vpcendpoints.Service,
	vpcAdvancedService vpcadvanced.Service,
	iamAdvancedService iamadvanced.Service,
	// Container security
	ecsSecService ecssecurity.Service,
	eksSecService ekssecurity.Service,
	// AI attack detection
	aiDetectionService aidetection.Service,
	// Historical storage
	storageService storage.Service,
) Service {
	return &service{
		stsService:           stsService,
		vpcService:           vpcService,
		iamService:           iamService,
		s3Service:            s3Service,
		cloudtrailService:    cloudtrailService,
		secretsService:       secretsService,
		securityhubSvc:       securityhubSvc,
		guarddutyService:     guarddutyService,
		apigatewayService:    apigatewayService,
		resourcePolSvc:       resourcePolSvc,
		outputService:        outputService,
		versionInfo:          versionInfo,
		shieldService:        shieldService,
		elbService:           elbService,
		route53Service:       route53Service,
		inspectorService:     inspectorService,
		lambdaSecService:     lambdaSecService,
		messagingService:     messagingService,
		cloudtrailSecService: cloudtrailSecService,
		configService:        configService,
		dataprotectionSvc:    dataprotectionSvc,
		loggingService:       loggingService,
		governanceService:    governanceService,
		vpcEndpointsService:  vpcEndpointsService,
		vpcAdvancedService:   vpcAdvancedService,
		iamAdvancedService:   iamAdvancedService,
		ecsSecService:        ecsSecService,
		eksSecService:        eksSecService,
		aiDetectionService:   aiDetectionService,
		storageService:       storageService,
	}
}

func (s *service) Orchestrate(flags model.Flags) error {
	if flags.Version {
		return s.versionWorkflow()
	}

	return s.securityWorkflow(flags)
}

func (s *service) versionWorkflow() error {
	s.outputService.StopSpinner()

	fmt.Printf("aws-perimeter version %s\n", s.versionInfo.Version)
	fmt.Printf("commit: %s\n", s.versionInfo.Commit)
	fmt.Printf("built at: %s\n", s.versionInfo.Date)

	return nil
}

func (s *service) securityWorkflow(flags model.Flags) error {
	startedAt := time.Now()
	scanCtx := context.Background()
	g, groupCtx := errgroup.WithContext(scanCtx)

	// VPC Security Results
	var (
		sgRisks       []vpc.SGRisk
		unusedSGs     []vpc.UnusedSG
		exposureRisks []vpc.ExposureRisk
		naclRisks     []vpc.NACLRisk
		flowLogStatus []vpc.FlowLogStatus
		// Phase T: Nation-State Threat Detection
		mgmtExposure   []vpc.ManagementExposure
		plaintextRisks []vpc.PlaintextRisk
		imdsv1Risks    []vpc.IMDSv1Risk
	)

	// IAM Security Results
	var (
		privEscRisks      []iam.PrivEscRisk
		staleCreds        []iam.StaleCredential
		crossAcctTrusts   []iam.CrossAccountTrust
		usersWithoutMFA   []iam.UserMFAStatus
		dangerousPolicies []iam.DangerousPolicy
		missingBoundaries []iam.PermissionBoundary
	)

	// S3 Security Results
	var (
		publicBuckets   []s3security.BucketRisk
		unencryptedBkts []s3security.BucketEncryption
		riskyPolicies   []s3security.BucketPolicy
	)

	// CloudTrail Results
	var (
		trailStatus []cloudtrail.TrailStatus
		trailGaps   []cloudtrail.TrailGap
	)

	// Secrets Results
	var (
		lambdaSecrets []secrets.SecretFinding
		ec2Secrets    []secrets.SecretFinding
		s3Secrets     []secrets.SecretFinding
	)

	// New Services Results
	var (
		hubStatus         *securityhub.HubStatus
		hubStandards      []securityhub.StandardStatus
		hubFindings       []securityhub.CriticalFinding
		gdStatus          *guardduty.DetectorStatus
		gdFindings        []guardduty.ThreatFinding
		apiNoRateLimits   []apigateway.RateLimitStatus
		apiNoAuth         []apigateway.AuthorizationStatus
		apiRisks          []apigateway.APIRisk
		lambdaPolicyRisks []resourcepolicy.ResourcePolicyRisk
		sqsPolicyRisks    []resourcepolicy.ResourcePolicyRisk
		snsPolicyRisks    []resourcepolicy.ResourcePolicyRisk
	)

	// Extended Security Services Results
	var (
		// Shield/ELB
		shieldStatus  *shield.DDoSProtectionStatus
		albRisks      []elb.ALBSecurityRisk
		listenerRisks []elb.ListenerSecurityRisk
		// Lambda Security
		lambdaRoles    []lambdasecurity.OverlyPermissiveRole
		lambdaCrossReg []lambdasecurity.CrossRegionExecution
		// CloudTrail Security
		roleCreations []cloudtrailsecurity.IAMRoleCreationEvent
		rootUsage     []cloudtrailsecurity.RootAccountUsage
		// Config/KMS
		configStatus  *config.ConfigStatus
		ebsEncryption *config.EBSEncryptionStatus
		kmsRotation   []config.KMSKeyRotation
		// Data Protection
		rdsRisks     []dataprotection.RDSSecurityRisk
		dynamoRisks  []dataprotection.DynamoDBRisk
		secretRisks  []dataprotection.SecretRotationRisk
		backupStatus *dataprotection.BackupStatus
		// VPC Endpoints
		endpointStatus   *vpcendpoints.EndpointStatus
		endpointRisks    []vpcendpoints.EndpointRisk
		natStatus        *vpcendpoints.NATGatewayStatus
		missingEndpoints []vpcendpoints.MissingEndpoint
		// VPC Advanced
		peeringRisks []vpcadvanced.VPCPeeringRisk
		bastionHosts []vpcadvanced.BastionHost
		subnetClass  []vpcadvanced.SubnetClassification
		// IAM Advanced
		roleChainRisks   []iamadvanced.RoleChainRisk
		externalIDRisks  []iamadvanced.ExternalIDRisk
		boundaryRisks    []iamadvanced.PermissionBoundaryRisk
		instanceProfiles []iamadvanced.InstanceProfileRisk
		// Container Security
		ecsRisks []ecssecurity.ECSRisk
		eksRisks []ekssecurity.EKSRisk
		// AI Attack Detection
		aiRisks []aidetection.AIRisk
	)

	var stsResult *sts.GetCallerIdentityOutput

	// Fetch caller identity first
	g.Go(func() error {
		var err error
		stsResult, err = s.stsService.GetCallerIdentity(groupCtx)
		return err
	})

	// VPC Security Checks
	g.Go(func() error {
		var err error
		sgRisks, err = s.vpcService.GetSecurityGroupRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		unusedSGs, err = s.vpcService.GetUnusedSecurityGroups(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		exposureRisks, err = s.vpcService.GetPublicExposureRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		naclRisks, err = s.vpcService.GetNACLRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		flowLogStatus, err = s.vpcService.GetVPCFlowLogStatus(groupCtx)
		return err
	})

	// Phase T: Nation-State Threat Detection
	g.Go(func() error {
		var err error
		mgmtExposure, err = s.vpcService.GetManagementExposureRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		plaintextRisks, err = s.vpcService.GetPlaintextProtocolRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		imdsv1Risks, err = s.vpcService.GetIMDSv1Risks(groupCtx)
		return err
	})

	// IAM Security Checks
	g.Go(func() error {
		var err error
		privEscRisks, err = s.iamService.GetPrivilegeEscalationRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		staleCreds, err = s.iamService.GetStaleCredentials(groupCtx, 90)
		return err
	})
	g.Go(func() error {
		var err error
		usersWithoutMFA, err = s.iamService.GetUsersWithoutMFA(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		dangerousPolicies, err = s.iamService.GetOverlyPermissivePolicies(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		missingBoundaries, err = s.iamService.GetMissingBoundaries(groupCtx)
		return err
	})

	// S3 Security Checks
	g.Go(func() error {
		var err error
		publicBuckets, err = s.s3Service.GetPublicBuckets(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		unencryptedBkts, err = s.s3Service.GetUnencryptedBuckets(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		riskyPolicies, err = s.s3Service.GetRiskyBucketPolicies(groupCtx)
		return err
	})

	// CloudTrail Checks
	g.Go(func() error {
		var err error
		trailStatus, err = s.cloudtrailService.GetTrailStatus(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		trailGaps, err = s.cloudtrailService.GetTrailGaps(groupCtx)
		return err
	})

	// Secrets Detection
	g.Go(func() error {
		var err error
		lambdaSecrets, err = s.secretsService.ScanLambdaEnvVars(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		ec2Secrets, err = s.secretsService.ScanEC2UserData(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		s3Secrets, err = s.secretsService.ScanPublicS3Objects(groupCtx)
		return err
	})

	// Security Hub
	g.Go(func() error {
		var err error
		hubStatus, err = s.securityhubSvc.GetHubStatus(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		hubStandards, err = s.securityhubSvc.GetStandardsStatus(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		hubFindings, err = s.securityhubSvc.GetCriticalFindings(groupCtx, 10)
		return err
	})

	// GuardDuty
	g.Go(func() error {
		var err error
		gdStatus, err = s.guarddutyService.GetDetectorStatus(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		gdFindings, err = s.guarddutyService.GetThreatFindings(groupCtx, 10)
		return err
	})

	// API Gateway
	g.Go(func() error {
		var err error
		apiNoRateLimits, err = s.apigatewayService.GetAPIsWithoutRateLimits(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		apiNoAuth, err = s.apigatewayService.GetUnauthorizedRoutes(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		apiRisks, err = s.apigatewayService.GetAPIRisks(groupCtx)
		return err
	})

	// Resource-based Policies
	g.Go(func() error {
		var err error
		lambdaPolicyRisks, err = s.resourcePolSvc.GetLambdaPolicyRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		sqsPolicyRisks, err = s.resourcePolSvc.GetSQSPolicyRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		snsPolicyRisks, err = s.resourcePolSvc.GetSNSPolicyRisks(groupCtx)
		return err
	})

	// Extended Security Services
	// Shield/ELB
	g.Go(func() error {
		var err error
		shieldStatus, err = s.shieldService.GetDDoSProtectionStatus(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		albRisks, err = s.elbService.GetALBSecurityRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		listenerRisks, err = s.elbService.GetListenerSecurityRisks(groupCtx)
		return err
	})

	// Lambda Security
	g.Go(func() error {
		var err error
		lambdaRoles, err = s.lambdaSecService.GetOverlyPermissiveRoles(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		lambdaCrossReg, err = s.lambdaSecService.GetCrossRegionExecution(groupCtx)
		return err
	})

	// CloudTrail Security
	g.Go(func() error {
		var err error
		roleCreations, err = s.cloudtrailSecService.GetRecentRoleCreations(groupCtx, 24)
		return err
	})
	g.Go(func() error {
		var err error
		rootUsage, err = s.cloudtrailSecService.GetRootAccountUsage(groupCtx, 168) // 7 days
		return err
	})

	// Config/KMS
	g.Go(func() error {
		var err error
		configStatus, err = s.configService.GetConfigStatus(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		ebsEncryption, err = s.configService.GetEBSEncryptionStatus(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		kmsRotation, err = s.configService.GetKMSKeyRotationStatus(groupCtx)
		return err
	})

	// Data Protection
	g.Go(func() error {
		var err error
		rdsRisks, err = s.dataprotectionSvc.GetRDSSecurityRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		dynamoRisks, err = s.dataprotectionSvc.GetDynamoDBRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		secretRisks, err = s.dataprotectionSvc.GetSecretRotationRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		backupStatus, err = s.dataprotectionSvc.GetBackupStatus(groupCtx)
		return err
	})

	// VPC Endpoints
	g.Go(func() error {
		var err error
		endpointStatus, err = s.vpcEndpointsService.GetEndpointStatus(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		endpointRisks, err = s.vpcEndpointsService.GetEndpointRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		natStatus, err = s.vpcEndpointsService.GetNATStatus(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		missingEndpoints, err = s.vpcEndpointsService.GetMissingEndpoints(groupCtx)
		return err
	})

	// VPC Advanced
	g.Go(func() error {
		var err error
		peeringRisks, err = s.vpcAdvancedService.GetVPCPeeringRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		bastionHosts, err = s.vpcAdvancedService.GetBastionHosts(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		subnetClass, err = s.vpcAdvancedService.GetSubnetClassification(groupCtx)
		return err
	})

	// IAM Advanced
	g.Go(func() error {
		var err error
		roleChainRisks, err = s.iamAdvancedService.GetRoleChainRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		externalIDRisks, err = s.iamAdvancedService.GetExternalIDRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		boundaryRisks, err = s.iamAdvancedService.GetPermissionBoundaryRisks(groupCtx)
		return err
	})
	g.Go(func() error {
		var err error
		instanceProfiles, err = s.iamAdvancedService.GetInstanceProfileRisks(groupCtx)
		return err
	})

	// Container Security
	g.Go(func() error {
		var err error
		if s.ecsSecService != nil {
			ecsRisks, err = s.ecsSecService.GetECSRisks(groupCtx)
		}
		return err
	})
	g.Go(func() error {
		var err error
		if s.eksSecService != nil {
			eksRisks, err = s.eksSecService.GetEKSRisks(groupCtx)
		}
		return err
	})

	// AI Attack Detection
	g.Go(func() error {
		var err error
		if s.aiDetectionService != nil {
			aiRisks, err = s.aiDetectionService.GetAIRisks(groupCtx)
		}
		return err
	})

	// Wait for all goroutines
	if err := g.Wait(); err != nil {
		return err
	}

	// Cross-account check needs account ID
	crossAcctTrusts, _ = s.iamService.GetCrossAccountTrusts(scanCtx, *stsResult.Account)

	s.outputService.StopSpinner()

	// Print report header with Amazon orange color
	orange := "\033[38;2;255;153;0m" // Amazon Orange #FF9900
	reset := "\033[0m"
	fmt.Printf("\n%s🔐 AWS Perimeter v%s - Security Posture Report - Account: %s - Region: %s%s\n", orange, s.versionInfo.Version, *stsResult.Account, flags.Region, reset)

	// Render all outputs
	vpcInput := model.RenderSecurityInput{
		AccountID:            *stsResult.Account,
		Region:               flags.Region,
		SecurityGroupRisks:   sgRisks,
		UnusedSecurityGroups: unusedSGs,
		PublicExposureRisks:  exposureRisks,
		NACLRisks:            naclRisks,
		VPCFlowLogStatus:     flowLogStatus,
		// Phase T: Nation-State Threat Detection
		ManagementExposure: mgmtExposure,
		PlaintextRisks:     plaintextRisks,
		IMDSv1Risks:        imdsv1Risks,
	}
	if err := s.outputService.RenderSecurity(vpcInput); err != nil {
		return err
	}

	iamInput := model.RenderIAMInput{
		AccountID:                *stsResult.Account,
		Region:                   flags.Region,
		PrivilegeEscalation:      privEscRisks,
		StaleCredentials:         staleCreds,
		CrossAccountTrusts:       crossAcctTrusts,
		UsersWithoutMFA:          usersWithoutMFA,
		OverlyPermissivePolicies: dangerousPolicies,
		MissingBoundaries:        missingBoundaries,
	}
	if err := s.outputService.RenderIAM(iamInput); err != nil {
		return err
	}

	s3Input := model.RenderS3Input{
		AccountID:       *stsResult.Account,
		Region:          flags.Region,
		PublicBuckets:   publicBuckets,
		UnencryptedBkts: unencryptedBkts,
		RiskyPolicies:   riskyPolicies,
	}
	if err := s.outputService.RenderS3(s3Input); err != nil {
		return err
	}

	ctInput := model.RenderCloudTrailInput{
		AccountID:   *stsResult.Account,
		Region:      flags.Region,
		TrailStatus: trailStatus,
		TrailGaps:   trailGaps,
	}
	if err := s.outputService.RenderCloudTrail(ctInput); err != nil {
		return err
	}

	secretsInput := model.RenderSecretsInput{
		AccountID:     *stsResult.Account,
		Region:        flags.Region,
		LambdaSecrets: lambdaSecrets,
		EC2Secrets:    ec2Secrets,
		S3Secrets:     s3Secrets,
	}
	if err := s.outputService.RenderSecrets(secretsInput); err != nil {
		return err
	}

	// New checks
	advInput := model.RenderAdvancedInput{
		AccountID:         *stsResult.Account,
		Region:            flags.Region,
		HubStatus:         hubStatus,
		HubStandards:      hubStandards,
		HubFindings:       hubFindings,
		GuardDutyStatus:   gdStatus,
		GuardDutyFindings: gdFindings,
		APINoRateLimits:   apiNoRateLimits,
		APINoAuth:         apiNoAuth,
		APIRisks:          apiRisks,
		LambdaPolicyRisks: lambdaPolicyRisks,
		SQSPolicyRisks:    sqsPolicyRisks,
		SNSPolicyRisks:    snsPolicyRisks,
	}
	if err := s.outputService.RenderAdvanced(advInput); err != nil {
		return err
	}

	// Extended Security Checks
	extInput := extratables.ExtendedSecurityInput{
		AccountID:        *stsResult.Account,
		ShieldStatus:     shieldStatus,
		ALBRisks:         albRisks,
		ListenerRisks:    listenerRisks,
		LambdaRoles:      lambdaRoles,
		LambdaCrossReg:   lambdaCrossReg,
		RoleCreations:    roleCreations,
		RootUsage:        rootUsage,
		ConfigStatus:     configStatus,
		EBSEncryption:    ebsEncryption,
		KMSRotation:      kmsRotation,
		RDSRisks:         rdsRisks,
		DynamoRisks:      dynamoRisks,
		SecretRisks:      secretRisks,
		BackupStatus:     backupStatus,
		EndpointStatus:   endpointStatus,
		EndpointRisks:    endpointRisks,
		NATStatus:        natStatus,
		MissingEndpoints: missingEndpoints,
		PeeringRisks:     peeringRisks,
		BastionHosts:     bastionHosts,
		SubnetClass:      subnetClass,
		RoleChainRisks:   roleChainRisks,
		ExternalIDRisks:  externalIDRisks,
		BoundaryRisks:    boundaryRisks,
		InstanceProfiles: instanceProfiles,
	}
	extratables.DrawExtendedSecurityTable(extInput)

	if err := s.persistScanIfEnabled(
		scanCtx,
		flags,
		*stsResult.Account,
		flags.Region,
		time.Since(startedAt),
		vpcInput,
		iamInput,
		s3Input,
		ctInput,
		secretsInput,
		advInput,
		aiRisks,
	); err != nil {
		return fmt.Errorf("failed to persist scan: %w", err)
	}

	// Generate HTML report if requested
	if flags.Output == "html" && flags.OutputFile != "" {
		sections := []htmloutput.Section{}

		// VPC Section - Complete
		vpcFindings := []htmloutput.Finding{}
		for _, sg := range sgRisks {
			vpcFindings = append(vpcFindings, htmloutput.Finding{
				Severity: sg.Severity, Title: "Security Group Risk: " + sg.RiskType,
				Resource: sg.SecurityGroupName, Description: sg.Description, Recommendation: sg.Recommendation,
			})
		}
		for _, vpc := range flowLogStatus {
			if !vpc.FlowLogsEnabled {
				resource := vpc.VpcName
				if resource == "" {
					resource = vpc.VpcID
				}
				vpcFindings = append(vpcFindings, htmloutput.Finding{
					Severity: "MEDIUM", Title: "VPC Missing Flow Logs",
					Resource: resource, Description: "VPC does not have flow logs enabled",
				})
			}
		}
		for _, nacl := range naclRisks {
			vpcFindings = append(vpcFindings, htmloutput.Finding{
				Severity: nacl.Severity, Title: "NACL Risk",
				Resource: nacl.NetworkAclID, Description: nacl.Description,
			})
		}
		for _, exp := range exposureRisks {
			vpcFindings = append(vpcFindings, htmloutput.Finding{
				Severity: exp.Severity, Title: "Public Exposure",
				Resource: exp.InstanceID, Description: exp.Description,
			})
		}
		for _, unused := range unusedSGs {
			vpcFindings = append(vpcFindings, htmloutput.Finding{
				Severity: "INFO", Title: "Unused Security Group",
				Resource: unused.SecurityGroupName, Description: "Security group is not attached to any resources",
			})
		}
		for _, mgmt := range mgmtExposure {
			vpcFindings = append(vpcFindings, htmloutput.Finding{
				Severity: mgmt.Severity, Title: "Management Port Exposure",
				Resource: mgmt.InstanceID, Description: mgmt.Description,
			})
		}
		for _, pt := range plaintextRisks {
			vpcFindings = append(vpcFindings, htmloutput.Finding{
				Severity: pt.Severity, Title: "Plaintext Protocol Risk",
				Resource: pt.SecurityGroupID, Description: pt.Description,
			})
		}
		for _, imds := range imdsv1Risks {
			vpcFindings = append(vpcFindings, htmloutput.Finding{
				Severity: imds.Severity, Title: "IMDSv1 Enabled",
				Resource: imds.InstanceID, Description: imds.Description,
			})
		}
		sections = append(sections, htmloutput.NewVPCSection(vpcFindings))

		// IAM Section - Complete
		iamFindings := []htmloutput.Finding{}
		for _, user := range usersWithoutMFA {
			if !user.MFAEnabled {
				iamFindings = append(iamFindings, htmloutput.Finding{
					Severity: "HIGH", Title: "User Without MFA",
					Resource: user.UserName, Description: "IAM user does not have MFA enabled",
				})
			}
		}
		for _, pe := range privEscRisks {
			iamFindings = append(iamFindings, htmloutput.Finding{
				Severity: pe.Severity, Title: "Privilege Escalation Risk",
				Resource: pe.PrincipalName, Description: pe.EscalationPath,
			})
		}
		for _, stale := range staleCreds {
			iamFindings = append(iamFindings, htmloutput.Finding{
				Severity: stale.Severity, Title: "Stale Credentials",
				Resource: stale.UserName, Description: fmt.Sprintf("Last used %d days ago", stale.DaysSinceLastUse),
			})
		}
		for _, ca := range crossAcctTrusts {
			iamFindings = append(iamFindings, htmloutput.Finding{
				Severity: ca.Severity, Title: "Cross-Account Trust",
				Resource: ca.RoleName, Description: "Trusts account: " + ca.TrustedAccountID,
			})
		}
		for _, dp := range dangerousPolicies {
			iamFindings = append(iamFindings, htmloutput.Finding{
				Severity: dp.Severity, Title: "Overly Permissive Policy",
				Resource: dp.PolicyName, Description: dp.Recommendation,
			})
		}
		for _, mb := range missingBoundaries {
			iamFindings = append(iamFindings, htmloutput.Finding{
				Severity: mb.Severity, Title: "Missing Permission Boundary",
				Resource: mb.PrincipalName, Description: "Principal has no permission boundary",
			})
		}
		sections = append(sections, htmloutput.NewIAMSection(iamFindings))

		// S3 Section - Complete
		s3Findings := []htmloutput.Finding{}
		for _, bucket := range publicBuckets {
			s3Findings = append(s3Findings, htmloutput.Finding{
				Severity: bucket.Severity, Title: "Public S3 Bucket",
				Resource: bucket.BucketName, Description: bucket.Description,
			})
		}
		for _, bucket := range unencryptedBkts {
			s3Findings = append(s3Findings, htmloutput.Finding{
				Severity: bucket.Severity, Title: "Unencrypted S3 Bucket",
				Resource: bucket.BucketName, Description: "Bucket is not encrypted: " + bucket.EncryptionType,
			})
		}
		for _, policy := range riskyPolicies {
			if policy.AllowsPublic || policy.AllowsAnyAction {
				s3Findings = append(s3Findings, htmloutput.Finding{
					Severity: policy.Severity, Title: "Risky Bucket Policy",
					Resource: policy.BucketName, Description: "Bucket policy allows public or any action",
				})
			}
		}
		sections = append(sections, htmloutput.NewS3Section(s3Findings))

		// CloudTrail Section - Complete
		ctFindings := []htmloutput.Finding{}
		for _, status := range trailStatus {
			if !status.IsLogging {
				ctFindings = append(ctFindings, htmloutput.Finding{
					Severity: "CRITICAL", Title: "CloudTrail Not Logging",
					Resource: status.TrailName, Description: "Trail is not actively logging",
				})
			} else if !status.IsMultiRegion {
				ctFindings = append(ctFindings, htmloutput.Finding{
					Severity: "MEDIUM", Title: "Single Region Trail",
					Resource: status.TrailName, Description: "Trail is not multi-region",
				})
			}
		}
		for _, gap := range trailGaps {
			ctFindings = append(ctFindings, htmloutput.Finding{
				Severity: gap.Severity, Title: "CloudTrail Gap",
				Resource: gap.Issue, Description: gap.Description,
			})
		}
		for _, root := range rootUsage {
			ctFindings = append(ctFindings, htmloutput.Finding{
				Severity: root.Severity, Title: "Root Account Usage Detected",
				Resource: root.EventName, Description: root.Description,
			})
		}
		sections = append(sections, htmloutput.NewCloudTrailSection(ctFindings))

		// Secrets Section
		secretsFindings := []htmloutput.Finding{}
		for _, secret := range lambdaSecrets {
			secretsFindings = append(secretsFindings, htmloutput.Finding{
				Severity: secret.Severity, Title: "Hardcoded Secret in Lambda",
				Resource: secret.ResourceName, Description: secret.SecretType,
			})
		}
		for _, secret := range ec2Secrets {
			secretsFindings = append(secretsFindings, htmloutput.Finding{
				Severity: secret.Severity, Title: "Hardcoded Secret in EC2 User Data",
				Resource: secret.ResourceName, Description: secret.SecretType,
			})
		}
		for _, secret := range s3Secrets {
			secretsFindings = append(secretsFindings, htmloutput.Finding{
				Severity: secret.Severity, Title: "Secret in Public S3 Bucket",
				Resource: secret.ResourceID, Description: secret.SecretType + " in " + secret.Location,
			})
		}
		sections = append(sections, htmloutput.NewSecretsSection(secretsFindings))

		// Advanced Section - Security Hub & GuardDuty
		advFindings := []htmloutput.Finding{}
		if hubStatus != nil && !hubStatus.IsEnabled {
			advFindings = append(advFindings, htmloutput.Finding{
				Severity: "HIGH", Title: "Security Hub Disabled",
				Resource: "Security Hub", Description: "AWS Security Hub is not enabled",
			})
		}
		for _, finding := range hubFindings {
			advFindings = append(advFindings, htmloutput.Finding{
				Severity: finding.Severity, Title: finding.Title,
				Resource: finding.ResourceID, Description: finding.Description,
			})
		}
		if gdStatus != nil && !gdStatus.IsEnabled {
			advFindings = append(advFindings, htmloutput.Finding{
				Severity: "HIGH", Title: "GuardDuty Disabled",
				Resource: "GuardDuty", Description: "AWS GuardDuty is not enabled",
			})
		}
		for _, finding := range gdFindings {
			advFindings = append(advFindings, htmloutput.Finding{
				Severity: finding.SeverityLabel, Title: finding.Type,
				Resource: finding.ResourceID, Description: finding.Description,
			})
		}
		sections = append(sections, htmloutput.NewAdvancedSection(advFindings))

		// Extended Section - All remaining checks
		extFindings := []htmloutput.Finding{}
		for _, risk := range albRisks {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: risk.Severity, Title: "ALB Security Risk",
				Resource: risk.LoadBalancerName, Description: risk.Description,
			})
		}
		for _, risk := range listenerRisks {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: risk.Severity, Title: "ALB Listener Risk",
				Resource: risk.ListenerARN, Description: risk.Description,
			})
		}
		for _, role := range lambdaRoles {
			if role.HasAdminAccess {
				extFindings = append(extFindings, htmloutput.Finding{
					Severity: role.Severity, Title: "Lambda Overly Permissive Role",
					Resource: role.FunctionName, Description: role.Description,
				})
			}
		}
		// configStatus and ebsEncryption are pointers, handle them directly
		if configStatus != nil && !configStatus.IsEnabled {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: "HIGH", Title: "AWS Config Disabled",
				Resource: "AWS Config", Description: configStatus.Description,
			})
		}
		if ebsEncryption != nil && !ebsEncryption.DefaultEncryptionEnabled {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: "MEDIUM", Title: "EBS Default Encryption Disabled",
				Resource: "EBS", Description: ebsEncryption.Description,
			})
		}
		for _, key := range kmsRotation {
			if !key.RotationEnabled {
				extFindings = append(extFindings, htmloutput.Finding{
					Severity: key.Severity, Title: "KMS Key Rotation Disabled",
					Resource: key.KeyID, Description: "KMS key does not have rotation enabled",
				})
			}
		}
		for _, rds := range rdsRisks {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: rds.Severity, Title: "RDS Security Risk",
				Resource: rds.DBInstanceID, Description: rds.Description,
			})
		}
		for _, dynamo := range dynamoRisks {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: dynamo.Severity, Title: "DynamoDB Risk",
				Resource: dynamo.TableName, Description: dynamo.Description,
			})
		}
		for _, secret := range secretRisks {
			if !secret.RotationEnabled {
				extFindings = append(extFindings, htmloutput.Finding{
					Severity: secret.Severity, Title: "Secret Rotation Disabled",
					Resource: secret.SecretName, Description: secret.Description,
				})
			}
		}
		for _, ep := range endpointRisks {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: ep.Severity, Title: "VPC Endpoint Risk",
				Resource: ep.EndpointID, Description: ep.Description,
			})
		}
		// natStatus is a pointer, handle it based on SingleAZRisk
		if natStatus != nil && natStatus.SingleAZRisk {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: "MEDIUM", Title: "NAT Gateway Single AZ Risk",
				Resource: "NAT", Description: natStatus.Description,
			})
		}
		for _, peer := range peeringRisks {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: peer.Severity, Title: "VPC Peering Risk",
				Resource: peer.PeeringID, Description: peer.Description,
			})
		}
		for _, bastion := range bastionHosts {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: "MEDIUM", Title: "Bastion Host Detected",
				Resource: bastion.InstanceID, Description: bastion.Description,
			})
		}
		for _, chain := range roleChainRisks {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: chain.Severity, Title: "Role Chain Risk",
				Resource: chain.RoleName, Description: chain.Description,
			})
		}
		for _, ext := range externalIDRisks {
			if !ext.HasExternalID {
				extFindings = append(extFindings, htmloutput.Finding{
					Severity: ext.Severity, Title: "Missing External ID",
					Resource: ext.RoleName, Description: ext.Description,
				})
			}
		}
		// Additional findings to sync with console output
		for _, crossReg := range lambdaCrossReg {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: crossReg.Severity, Title: "Lambda Cross-Region Execution",
				Resource: crossReg.FunctionName, Description: crossReg.Description,
			})
		}
		for _, roleCreate := range roleCreations {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: roleCreate.Severity, Title: "Suspicious IAM Role Creation",
				Resource: roleCreate.RoleName, Description: roleCreate.Description,
			})
		}
		if backupStatus != nil && backupStatus.VaultsCount == 0 {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: "MEDIUM", Title: "AWS Backup Not Configured",
				Resource: "AWS Backup", Description: backupStatus.Description,
			})
		}
		// Note: endpointStatus is a pointer with aggregate info, not a slice
		if endpointStatus != nil && !endpointStatus.S3EndpointExists && !endpointStatus.DynamoEndpointExists {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: endpointStatus.Severity, Title: "Missing Critical VPC Endpoints",
				Resource: "VPC Endpoints", Description: endpointStatus.Description,
			})
		}
		for _, missing := range missingEndpoints {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: missing.Severity, Title: "Missing VPC Endpoint",
				Resource: missing.ServiceName, Description: missing.Description,
			})
		}
		for _, boundary := range boundaryRisks {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: boundary.Severity, Title: "Permission Boundary Risk",
				Resource: boundary.PrincipalName, Description: boundary.Description,
			})
		}
		for _, profile := range instanceProfiles {
			if profile.HasOverlyPermissive {
				extFindings = append(extFindings, htmloutput.Finding{
					Severity: profile.Severity, Title: "Instance Profile with Admin Access",
					Resource: profile.InstanceProfileName, Description: profile.Description,
				})
			}
		}
		// Container Security - ECS
		for _, ecs := range ecsRisks {
			resource := ecs.ClusterName
			if ecs.ServiceName != "" {
				resource = ecs.ClusterName + "/" + ecs.ServiceName
			}
			if ecs.ContainerName != "" {
				resource = resource + "/" + ecs.ContainerName
			}
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: ecs.Severity, Title: "ECS: " + ecs.RiskType,
				Resource: resource, Description: ecs.Description, Recommendation: ecs.Recommendation,
			})
		}
		// Container Security - EKS
		for _, eks := range eksRisks {
			resource := eks.ClusterName
			if eks.NodeGroupName != "" {
				resource = eks.ClusterName + "/" + eks.NodeGroupName
			}
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: eks.Severity, Title: "EKS: " + eks.RiskType,
				Resource: resource, Description: eks.Description, Recommendation: eks.Recommendation,
			})
		}
		// AI Attack Detection
		for _, ai := range aiRisks {
			extFindings = append(extFindings, htmloutput.Finding{
				Severity: ai.Severity, Title: "AI: " + ai.RiskType,
				Resource: ai.Resource, Description: ai.Description, Recommendation: ai.Recommendation,
			})
		}
		sections = append(sections, htmloutput.NewExtendedSection(extFindings))

		reportData := htmloutput.ConvertFindingsToReportData(*stsResult.Account, sections)
		if err := htmloutput.WriteHTMLReport(flags.OutputFile, reportData); err != nil {
			return fmt.Errorf("failed to generate HTML report: %w", err)
		}
		fmt.Printf("\n✅ HTML report generated: %s\n", flags.OutputFile)
	}

	return nil
}
