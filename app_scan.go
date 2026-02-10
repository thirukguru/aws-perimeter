package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/thirukguru/aws-perimeter/model"
	"github.com/thirukguru/aws-perimeter/service/aidetection"
	"github.com/thirukguru/aws-perimeter/service/apigateway"
	awsconfig "github.com/thirukguru/aws-perimeter/service/aws_config"
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
	"github.com/thirukguru/aws-perimeter/service/orchestrator"
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
	"github.com/thirukguru/aws-perimeter/shared/spinner"
)

func runRegionScan(flags model.Flags, versionInfo model.VersionInfo, storageService storage.Service) error {
	cfgService := awsconfig.NewService()

	awsCfg, err := cfgService.GetAWSCfg(context.Background(), flags.Region, flags.Profile)
	if err != nil {
		return fmt.Errorf("failed to load AWS config for region %s: %w", flags.Region, err)
	}
	if flags.Region == "" {
		flags.Region = awsCfg.Region
	}

	spinner.StartSpinner()
	defer spinner.StopSpinner()

	stsService := awssts.NewService(awsCfg)
	vpcService := vpc.NewService(awsCfg)
	iamService := iam.NewService(awsCfg)
	s3Service := s3security.NewService(awsCfg)
	cloudtrailService := cloudtrail.NewService(awsCfg)
	secretsService := secrets.NewService(awsCfg)
	securityhubSvc := securityhub.NewService(awsCfg)
	guarddutyService := guardduty.NewService(awsCfg)
	apigatewayService := apigateway.NewService(awsCfg)
	resourcePolSvc := resourcepolicy.NewService(awsCfg)
	outputService := output.NewService(flags.Output)

	shieldService := shield.NewService(awsCfg)
	elbService := elb.NewService(awsCfg)
	route53Service := route53.NewService(awsCfg)
	inspectorService := inspector.NewService(awsCfg)
	lambdaSecService := lambdasecurity.NewService(awsCfg)
	messagingService := messaging.NewService(awsCfg)
	cloudtrailSecService := cloudtrailsecurity.NewService(awsCfg)
	configService := config.NewService(awsCfg)
	dataprotectionSvc := dataprotection.NewService(awsCfg)
	loggingService := logging.NewService(awsCfg)
	governanceService := governance.NewService(awsCfg)
	vpcEndpointsService := vpcendpoints.NewService(awsCfg)
	vpcAdvancedService := vpcadvanced.NewService(awsCfg)
	iamAdvancedService := iamadvanced.NewService(awsCfg)
	ecsSecService := ecssecurity.NewService(awsCfg)
	eksSecService := ekssecurity.NewService(awsCfg)
	aiDetectionService := aidetection.NewService(awsCfg)

	orchestratorService := orchestrator.NewService(
		stsService,
		vpcService,
		iamService,
		s3Service,
		cloudtrailService,
		secretsService,
		securityhubSvc,
		guarddutyService,
		apigatewayService,
		resourcePolSvc,
		outputService,
		versionInfo,
		shieldService,
		elbService,
		route53Service,
		inspectorService,
		lambdaSecService,
		messagingService,
		cloudtrailSecService,
		configService,
		dataprotectionSvc,
		loggingService,
		governanceService,
		vpcEndpointsService,
		vpcAdvancedService,
		iamAdvancedService,
		ecsSecService,
		eksSecService,
		aiDetectionService,
		storageService,
	)

	if err := orchestratorService.Orchestrate(flags); err != nil {
		return fmt.Errorf("security scan failed for region %s: %w", flags.Region, err)
	}
	return nil
}

func getAccountIDForFlags(flags model.Flags) (string, error) {
	cfgService := awsconfig.NewService()
	awsCfg, err := cfgService.GetAWSCfg(context.Background(), flags.Region, flags.Profile)
	if err != nil {
		return "", err
	}
	stsService := awssts.NewService(awsCfg)
	id, err := stsService.GetCallerIdentity(context.Background())
	if err != nil {
		return "", err
	}
	if id.Account == nil {
		return "", fmt.Errorf("unable to resolve account ID")
	}
	return *id.Account, nil
}

func runMultiRegionScans(flags model.Flags, versionInfo model.VersionInfo, storageService storage.Service) error {
	regions, err := resolveRegions(flags)
	if err != nil {
		return err
	}
	for _, r := range regions {
		fmt.Printf("\n🌍 Scanning region: %s\n", r)
		regionalFlags := flags
		regionalFlags.Region = r
		if err := runRegionScan(regionalFlags, versionInfo, storageService); err != nil {
			return err
		}
	}
	return nil
}

func resolveRegions(flags model.Flags) ([]string, error) {
	if len(flags.Regions) > 0 {
		return dedupeRegions(flags.Regions), nil
	}
	if !flags.AllRegions {
		return nil, fmt.Errorf("resolveRegions called without --regions/--all-regions")
	}

	cfgService := awsconfig.NewService()
	awsCfg, err := cfgService.GetAWSCfg(context.Background(), flags.Region, flags.Profile)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for region discovery: %w", err)
	}

	ec2Client := ec2.NewFromConfig(awsCfg)
	out, err := ec2Client.DescribeRegions(context.Background(), &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to discover regions: %w", err)
	}

	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		if r.RegionName == nil || strings.TrimSpace(*r.RegionName) == "" {
			continue
		}
		regions = append(regions, *r.RegionName)
	}
	regions = dedupeRegions(regions)
	if len(regions) == 0 {
		return nil, fmt.Errorf("no enabled regions discovered")
	}
	return regions, nil
}

func dedupeRegions(input []string) []string {
	out := make([]string, 0, len(input))
	for _, r := range input {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}
