// Package main is the entry point for the aws-perimeter application.
package main

import (
	"context"
	"fmt"
	"os"

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
	"github.com/thirukguru/aws-perimeter/service/flag"
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
	awssts "github.com/thirukguru/aws-perimeter/service/sts"
	"github.com/thirukguru/aws-perimeter/service/vpc"
	"github.com/thirukguru/aws-perimeter/service/vpcadvanced"
	"github.com/thirukguru/aws-perimeter/service/vpcendpoints"
	"github.com/thirukguru/aws-perimeter/shared/banner"
	"github.com/thirukguru/aws-perimeter/shared/spinner"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	flagService := flag.NewService()

	flags, err := flagService.GetParsedFlags()
	if err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}

	versionInfo := model.VersionInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	if flags.Version {
		outputService := output.NewService(flags.Output)
		orchestratorService := orchestrator.NewService(
			nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			outputService, versionInfo,
			nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
			nil, nil, // ECS/EKS services
			nil, // AI detection
		)

		return orchestratorService.Orchestrate(flags)
	}

	banner.DrawBannerTitle()

	cfgService := awsconfig.NewService()

	awsCfg, err := cfgService.GetAWSCfg(context.Background(), flags.Region, flags.Profile)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	spinner.StartSpinner()

	defer spinner.StopSpinner()

	// Initialize core services
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

	// Initialize extended security services
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
	// Container security services
	ecsSecService := ecssecurity.NewService(awsCfg)
	eksSecService := ekssecurity.NewService(awsCfg)
	// AI attack detection
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
		// Extended services
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
		// Container security
		ecsSecService,
		eksSecService,
		// AI attack detection
		aiDetectionService,
	)

	if err := orchestratorService.Orchestrate(flags); err != nil {
		return fmt.Errorf("security scan failed: %w", err)
	}

	return nil
}
