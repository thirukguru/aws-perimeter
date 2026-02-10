package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsCfgLoader "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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
	"golang.org/x/sync/errgroup"
)

type orgAccount struct {
	ID   string
	Name string
}

func runRegionScan(flags model.Flags, versionInfo model.VersionInfo, storageService storage.Service) error {
	cfgService := awsconfig.NewService()
	awsCfg, err := cfgService.GetAWSCfg(context.Background(), flags.Region, flags.Profile)
	if err != nil {
		return fmt.Errorf("failed to load AWS config for region %s: %w", flags.Region, err)
	}
	if flags.Region == "" {
		flags.Region = awsCfg.Region
	}
	return runConfiguredScan(awsCfg, flags, versionInfo, storageService, true)
}

func runConfiguredScan(
	awsCfg aws.Config,
	flags model.Flags,
	versionInfo model.VersionInfo,
	storageService storage.Service,
	useSpinner bool,
) error {
	if flags.Region == "" {
		flags.Region = awsCfg.Region
	}
	if useSpinner {
		spinner.StartSpinner()
		defer spinner.StopSpinner()
	}

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
	cfgService := awsconfig.NewService()
	baseCfg, err := cfgService.GetAWSCfg(context.Background(), flags.Region, flags.Profile)
	if err != nil {
		return fmt.Errorf("failed to load AWS config for multi-region scan: %w", err)
	}

	regions, err := resolveRegionsFromConfig(flags, baseCfg)
	if err != nil {
		return err
	}
	parallel := flags.MaxParallel
	if parallel <= 0 {
		parallel = 3
	}
	var printMu sync.Mutex
	g, ctx := errgroup.WithContext(context.Background())
	sem := make(chan struct{}, parallel)

	for _, r := range regions {
		region := r
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
			defer func() { <-sem }()

			printMu.Lock()
			fmt.Printf("\n🌍 Scanning region: %s\n", region)
			printMu.Unlock()

			regionalFlags := flags
			regionalFlags.Region = region
			cfg := baseCfg
			cfg.Region = region
			return runScanWithRetry(cfg, regionalFlags, versionInfo, storageService, false)
		})
	}
	return g.Wait()
}

func runOrgScans(flags model.Flags, versionInfo model.VersionInfo, storageService storage.Service) error {
	cfgService := awsconfig.NewService()
	baseCfg, err := cfgService.GetAWSCfg(context.Background(), flags.Region, flags.Profile)
	if err != nil {
		return fmt.Errorf("failed to load AWS config for org scan: %w", err)
	}

	accounts, managementAccountID, err := listOrgAccounts(baseCfg)
	if err != nil {
		return err
	}
	regions, err := resolveRegionsFromConfig(flags, baseCfg)
	if err != nil {
		return err
	}

	parallel := flags.MaxParallel
	if parallel <= 0 {
		parallel = 3
	}
	var printMu sync.Mutex
	g, ctx := errgroup.WithContext(context.Background())
	sem := make(chan struct{}, parallel)

	for _, a := range accounts {
		acct := a
		for _, r := range regions {
			region := r
			g.Go(func() error {
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return ctx.Err()
				}
				defer func() { <-sem }()

				printMu.Lock()
				fmt.Printf("\n🏢 Scanning account: %s (%s)\n", acct.Name, acct.ID)
				fmt.Printf("  🌍 Region: %s\n", region)
				printMu.Unlock()

				scanCfg := baseCfg
				scanCfg.Region = region
				if acct.ID != managementAccountID {
					assumedCfg, err := assumeAccountRole(baseCfg, acct.ID, region, flags.OrgRoleName, flags.ExternalID)
					if err != nil {
						printMu.Lock()
						fmt.Printf("  ⚠️ Skipping account %s in %s: %v\n", acct.ID, region, err)
						printMu.Unlock()
						return nil
					}
					scanCfg = assumedCfg
				}
				regionalFlags := flags
				regionalFlags.Region = region
				if err := runScanWithRetry(scanCfg, regionalFlags, versionInfo, storageService, false); err != nil {
					return fmt.Errorf("org scan failed for account %s region %s: %w", acct.ID, region, err)
				}
				return nil
			})
		}
	}
	return g.Wait()
}

func runScanWithRetry(
	cfg aws.Config,
	flags model.Flags,
	versionInfo model.VersionInfo,
	storageService storage.Service,
	useSpinner bool,
) error {
	const maxAttempts = 3
	backoff := 500 * time.Millisecond
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := runConfiguredScan(cfg, flags, versionInfo, storageService, useSpinner)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableScanError(err) || attempt == maxAttempts {
			return err
		}
		time.Sleep(backoff)
		backoff *= 2
	}
	return lastErr
}

func isRetryableScanError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "throttl") ||
		strings.Contains(msg, "rate exceeded") ||
		strings.Contains(msg, "request limit exceeded") ||
		strings.Contains(msg, "too many requests")
}

func listOrgAccounts(baseCfg aws.Config) ([]orgAccount, string, error) {
	ctx := context.Background()
	orgClient := organizations.NewFromConfig(baseCfg)
	stsClient := sts.NewFromConfig(baseCfg)

	caller, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, "", fmt.Errorf("failed to identify caller account: %w", err)
	}
	managementAccountID := aws.ToString(caller.Account)
	if managementAccountID == "" {
		return nil, "", fmt.Errorf("unable to resolve management account ID")
	}

	accounts := []orgAccount{}
	p := organizations.NewListAccountsPaginator(orgClient, &organizations.ListAccountsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to list organization accounts: %w", err)
		}
		for _, a := range page.Accounts {
			if a.Status != orgtypes.AccountStatusActive {
				continue
			}
			id := aws.ToString(a.Id)
			if id == "" {
				continue
			}
			accounts = append(accounts, orgAccount{ID: id, Name: aws.ToString(a.Name)})
		}
	}
	if len(accounts) == 0 {
		return nil, "", fmt.Errorf("no active organization accounts discovered")
	}
	return accounts, managementAccountID, nil
}

func assumeAccountRole(baseCfg aws.Config, accountID, region, roleName, externalID string) (aws.Config, error) {
	if roleName == "" {
		roleName = "OrganizationAccountAccessRole"
	}
	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
	stsClient := sts.NewFromConfig(baseCfg)

	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		if externalID != "" {
			o.ExternalID = aws.String(externalID)
		}
	})

	cfg, err := awsCfgLoader.LoadDefaultConfig(context.Background(),
		awsCfgLoader.WithRegion(region),
		awsCfgLoader.WithCredentialsProvider(aws.NewCredentialsCache(provider)),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load assumed role config (%s): %w", roleARN, err)
	}
	if _, err := cfg.Credentials.Retrieve(context.Background()); err != nil {
		return aws.Config{}, fmt.Errorf("failed to retrieve assumed role credentials (%s): %w", roleARN, err)
	}
	return cfg, nil
}

func resolveRegions(flags model.Flags) ([]string, error) {
	cfgService := awsconfig.NewService()
	baseCfg, err := cfgService.GetAWSCfg(context.Background(), flags.Region, flags.Profile)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for region discovery: %w", err)
	}
	return resolveRegionsFromConfig(flags, baseCfg)
}

func resolveRegionsFromConfig(flags model.Flags, awsCfg aws.Config) ([]string, error) {
	if len(flags.Regions) > 0 {
		return dedupeRegions(flags.Regions), nil
	}
	if !flags.AllRegions {
		if flags.Region != "" {
			return []string{flags.Region}, nil
		}
		if awsCfg.Region != "" {
			return []string{awsCfg.Region}, nil
		}
		return nil, fmt.Errorf("region is required unless --regions or --all-regions is used")
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
