package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
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
	"github.com/thirukguru/aws-perimeter/service/cachesecurity"
	"github.com/thirukguru/aws-perimeter/service/cloudtrail"
	"github.com/thirukguru/aws-perimeter/service/cloudtrailsecurity"
	"github.com/thirukguru/aws-perimeter/service/config"
	"github.com/thirukguru/aws-perimeter/service/dataprotection"
	"github.com/thirukguru/aws-perimeter/service/ecrsecurity"
	"github.com/thirukguru/aws-perimeter/service/ecssecurity"
	"github.com/thirukguru/aws-perimeter/service/ekssecurity"
	"github.com/thirukguru/aws-perimeter/service/elb"
	"github.com/thirukguru/aws-perimeter/service/eventsecurity"
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

type multiRegionScanDeps struct {
	resolveRegions func(model.Flags, aws.Config) ([]string, error)
	runScan        func(aws.Config, model.Flags, model.VersionInfo, storage.Service, bool) error
	runScanJSON    func(aws.Config, model.Flags, model.VersionInfo, storage.Service) (map[string]interface{}, error)
}

type orgScanDeps struct {
	listAccounts   func(aws.Config) ([]orgAccount, string, error)
	resolveRegions func(model.Flags, aws.Config) ([]string, error)
	assumeRole     func(aws.Config, string, string, string, string) (aws.Config, error)
	runScan        func(aws.Config, model.Flags, model.VersionInfo, storage.Service, bool) error
}

type fanoutScanResult struct {
	AccountID   string
	AccountName string
	Region      string
	Status      string
	Duration    time.Duration
	Error       string
}

type accountScanRollup struct {
	AccountID   string
	AccountName string
	Total       int
	Success     int
	Failed      int
	Skipped     int
}

type fanoutProgress struct {
	Total     int
	Completed int
	Success   int
	Failed    int
	Skipped   int
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
) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during security scan for region %s: %v\n%s", flags.Region, r, string(debug.Stack()))
		}
	}()

	if flags.Region == "" {
		flags.Region = awsCfg.Region
	}
	if useSpinner && flags.Output != "json" {
		spinner.StartSpinner()
		defer spinner.StopSpinner()
	}

	orchestratorService := buildOrchestratorService(awsCfg, flags.Output, versionInfo, storageService)
	if err := orchestratorService.Orchestrate(flags); err != nil {
		return fmt.Errorf("security scan failed for region %s: %w", flags.Region, err)
	}
	return nil
}

func buildOrchestratorService(
	awsCfg aws.Config,
	outputFormat string,
	versionInfo model.VersionInfo,
	storageService storage.Service,
) orchestrator.Service {
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
	outputService := output.NewService(outputFormat)

	shieldService := shield.NewService(awsCfg)
	elbService := elb.NewService(awsCfg)
	route53Service := route53.NewService(awsCfg)
	inspectorService := inspector.NewService(awsCfg)
	lambdaSecService := lambdasecurity.NewService(awsCfg)
	messagingService := messaging.NewService(awsCfg)
	ecrSecService := ecrsecurity.NewService(awsCfg)
	eventSecurityService := eventsecurity.NewService(awsCfg)
	cacheSecurityService := cachesecurity.NewService(awsCfg)
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

	return orchestrator.NewService(
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
		ecrSecService,
		eventSecurityService,
		cacheSecurityService,
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
	return runMultiRegionScansWithConfig(baseCfg, flags, versionInfo, storageService, multiRegionScanDeps{
		resolveRegions: resolveRegionsFromConfig,
		runScan:        runScanWithRetry,
		runScanJSON:    runScanJSONPayloadWithRetry,
	})
}

func runMultiRegionScansWithConfig(
	baseCfg aws.Config,
	flags model.Flags,
	versionInfo model.VersionInfo,
	storageService storage.Service,
	deps multiRegionScanDeps,
) error {
	accountID, accountName := resolveMultiRegionAccountIdentity(baseCfg, flags)

	regions, err := deps.resolveRegions(flags, baseCfg)
	if err != nil {
		return err
	}
	if flags.Output == "json" && deps.runScanJSON != nil {
		return runMultiRegionScansJSON(baseCfg, flags, versionInfo, storageService, regions, deps.runScanJSON)
	}
	results := make([]fanoutScanResult, 0, len(regions))
	progress := fanoutProgress{Total: len(regions)}
	parallel := flags.MaxParallel
	if parallel <= 0 {
		parallel = 3
	}
	if flags.Output == "json" || flags.Output == "html" {
		parallel = 1
	}
	var printMu sync.Mutex
	var resultMu sync.Mutex
	var errMu sync.Mutex
	var firstScanErr error
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

			if flags.Output != "json" {
				printMu.Lock()
				fmt.Printf("\n🌍 Scanning region: %s\n", region)
				printMu.Unlock()
			}

			regionalFlags := flags
			regionalFlags.Region = region
			if regionalFlags.Output == "html" && strings.TrimSpace(regionalFlags.OutputFile) != "" {
				regionalFlags.OutputFile = buildFanoutOutputFile(regionalFlags.OutputFile, "", region, time.Now())
			}
			cfg := baseCfg
			cfg.Region = region
			started := time.Now()
			scanErr := deps.runScan(cfg, regionalFlags, versionInfo, storageService, false)
			result := fanoutScanResult{
				AccountID:   accountID,
				AccountName: accountName,
				Region:      region,
				Status:      "SUCCESS",
				Duration:    time.Since(started),
			}
			if scanErr != nil {
				result.Status = "FAILED"
				result.Error = formatMultiRegionFailure(scanErr)
				errMu.Lock()
				if firstScanErr == nil {
					firstScanErr = scanErr
				}
				errMu.Unlock()
			}
			resultMu.Lock()
			results = append(results, result)
			snapshot := updateFanoutProgress(&progress, result.Status)
			resultMu.Unlock()
			if flags.Output != "json" {
				printMu.Lock()
				fmt.Printf("  Progress [%s]: %d/%d (success=%d failed=%d skipped=%d)\n",
					"Multi-Region", snapshot.Completed, snapshot.Total, snapshot.Success, snapshot.Failed, snapshot.Skipped)
				printMu.Unlock()
			}
			return nil
		})
	}
	waitErr := g.Wait()
	if flags.Output != "json" {
		renderFanoutSummary("Multi-Region", results)
	}
	if flags.BestEffort && hasScanSuccess(results) {
		return nil
	}
	if firstScanErr != nil {
		return firstScanErr
	}
	return waitErr
}

func resolveMultiRegionAccountIdentity(baseCfg aws.Config, flags model.Flags) (string, string) {
	accountID := strings.TrimSpace(flags.AccountID)
	// Use profile as friendly name in multi-region mode (single account fanout).
	accountName := strings.TrimSpace(flags.Profile)
	if accountName == "" {
		accountName = "current-account"
	}

	// Best-effort account ID lookup. Avoid provider resolution in tests where credentials are unset.
	if accountID == "" && baseCfg.Credentials != nil {
		stsClient := sts.NewFromConfig(baseCfg)
		if caller, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{}); err == nil {
			accountID = aws.ToString(caller.Account)
		}
	}

	if accountID == "" {
		accountID = "unknown-account"
	}
	return accountID, accountName
}

func runMultiRegionScansJSON(
	baseCfg aws.Config,
	flags model.Flags,
	versionInfo model.VersionInfo,
	storageService storage.Service,
	regions []string,
	runScanJSON func(aws.Config, model.Flags, model.VersionInfo, storage.Service) (map[string]interface{}, error),
) error {
	type regionError struct {
		Region string `json:"region"`
		Error  string `json:"error"`
	}
	type summary struct {
		TotalRegions int `json:"total_regions"`
		Success      int `json:"success"`
		Failed       int `json:"failed"`
		Skipped      int `json:"skipped"`
	}
	type aggregate struct {
		Tool        string                   `json:"tool"`
		Mode        string                   `json:"mode"`
		GeneratedAt string                   `json:"generated_at"`
		BestEffort  bool                     `json:"best_effort"`
		Summary     summary                  `json:"summary"`
		Results     []map[string]interface{} `json:"results"`
		Failures    []regionError            `json:"failures,omitempty"`
	}

	out := aggregate{
		Tool:        "aws-perimeter",
		Mode:        "multi-region",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		BestEffort:  flags.BestEffort,
		Summary: summary{
			TotalRegions: len(regions),
		},
		Results: make([]map[string]interface{}, 0, len(regions)),
	}

	var firstErr error
	for _, region := range regions {
		regionalFlags := flags
		regionalFlags.Region = region
		cfg := baseCfg
		cfg.Region = region

		payload, err := runScanJSON(cfg, regionalFlags, versionInfo, storageService)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			out.Summary.Failed++
			out.Failures = append(out.Failures, regionError{
				Region: region,
				Error:  formatMultiRegionFailure(err),
			})
			continue
		}
		out.Summary.Success++
		out.Results = append(out.Results, payload)
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal aggregated multi-region json: %w", err)
	}
	fmt.Println(string(b))

	if flags.BestEffort && out.Summary.Success > 0 {
		return nil
	}
	if firstErr != nil {
		return firstErr
	}
	return nil
}

func hasScanSuccess(results []fanoutScanResult) bool {
	for _, r := range results {
		if r.Status == "SUCCESS" {
			return true
		}
	}
	return false
}

func formatMultiRegionFailure(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("Try again after sometime. %s", err.Error())
}

func buildFanoutOutputFile(basePath, accountID, region string, t time.Time) string {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		return basePath
	}
	ext := filepath.Ext(basePath)
	dir := filepath.Dir(basePath)
	baseName := filepath.Base(basePath)
	nameOnly := strings.TrimSuffix(baseName, ext)
	if nameOnly == "" {
		nameOnly = "security-report"
	}

	suffixParts := []string{}
	if strings.TrimSpace(accountID) != "" {
		suffixParts = append(suffixParts, accountID)
	}
	if strings.TrimSpace(region) != "" {
		suffixParts = append(suffixParts, region)
	}
	suffix := strings.Join(suffixParts, "-")
	if suffix != "" {
		nameOnly = fmt.Sprintf("%s-%s", nameOnly, suffix)
	}
	if t.IsZero() {
		t = time.Now()
	}
	nameOnly = fmt.Sprintf("%s-%s", nameOnly, t.UTC().Format("20060102-150405"))

	fileName := nameOnly + ext
	if dir == "." || dir == "" {
		return fileName
	}
	return filepath.Join(dir, fileName)
}

func runOrgScans(flags model.Flags, versionInfo model.VersionInfo, storageService storage.Service) error {
	cfgService := awsconfig.NewService()
	baseCfg, err := cfgService.GetAWSCfg(context.Background(), flags.Region, flags.Profile)
	if err != nil {
		return fmt.Errorf("failed to load AWS config for org scan: %w", err)
	}
	return runOrgScansWithConfig(baseCfg, flags, versionInfo, storageService, orgScanDeps{
		listAccounts:   listOrgAccounts,
		resolveRegions: resolveRegionsFromConfig,
		assumeRole:     assumeAccountRole,
		runScan:        runScanWithRetry,
	})
}

func runOrgScansWithConfig(
	baseCfg aws.Config,
	flags model.Flags,
	versionInfo model.VersionInfo,
	storageService storage.Service,
	deps orgScanDeps,
) error {
	accounts, managementAccountID, err := deps.listAccounts(baseCfg)
	if err != nil {
		return err
	}
	regions, err := deps.resolveRegions(flags, baseCfg)
	if err != nil {
		return err
	}
	results := make([]fanoutScanResult, 0, len(accounts)*len(regions))
	progress := fanoutProgress{Total: len(accounts) * len(regions)}

	parallel := flags.MaxParallel
	if parallel <= 0 {
		parallel = 3
	}
	if flags.Output == "json" || flags.Output == "html" {
		parallel = 1
	}
	var printMu sync.Mutex
	var resultMu sync.Mutex
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

				if flags.Output != "json" {
					printMu.Lock()
					fmt.Printf("\n🏢 Scanning account: %s (%s)\n", acct.Name, acct.ID)
					fmt.Printf("  🌍 Region: %s\n", region)
					printMu.Unlock()
				}

				scanCfg := baseCfg
				scanCfg.Region = region
				if acct.ID != managementAccountID {
					assumedCfg, err := deps.assumeRole(baseCfg, acct.ID, region, flags.OrgRoleName, flags.ExternalID)
					if err != nil {
						if flags.Output != "json" {
							printMu.Lock()
							fmt.Printf("  ⚠️ Skipping account %s in %s: %v\n", acct.ID, region, err)
							printMu.Unlock()
						}
						resultMu.Lock()
						results = append(results, fanoutScanResult{
							AccountID:   acct.ID,
							AccountName: acct.Name,
							Region:      region,
							Status:      "SKIPPED",
							Error:       err.Error(),
						})
						snapshot := updateFanoutProgress(&progress, "SKIPPED")
						resultMu.Unlock()
						if flags.Output != "json" {
							printMu.Lock()
							fmt.Printf("  Progress [%s]: %d/%d (success=%d failed=%d skipped=%d)\n",
								"Org + Region", snapshot.Completed, snapshot.Total, snapshot.Success, snapshot.Failed, snapshot.Skipped)
							printMu.Unlock()
						}
						return nil
					}
					scanCfg = assumedCfg
				}
				regionalFlags := flags
				regionalFlags.Region = region
				if regionalFlags.Output == "html" && strings.TrimSpace(regionalFlags.OutputFile) != "" {
					regionalFlags.OutputFile = buildFanoutOutputFile(regionalFlags.OutputFile, acct.ID, region, time.Now())
				}
				started := time.Now()
				scanErr := deps.runScan(scanCfg, regionalFlags, versionInfo, storageService, false)
				result := fanoutScanResult{
					AccountID:   acct.ID,
					AccountName: acct.Name,
					Region:      region,
					Status:      "SUCCESS",
					Duration:    time.Since(started),
				}
				if scanErr != nil {
					result.Status = "FAILED"
					result.Error = scanErr.Error()
				}
				resultMu.Lock()
				results = append(results, result)
				snapshot := updateFanoutProgress(&progress, result.Status)
				resultMu.Unlock()
				if flags.Output != "json" {
					printMu.Lock()
					fmt.Printf("  Progress [%s]: %d/%d (success=%d failed=%d skipped=%d)\n",
						"Org + Region", snapshot.Completed, snapshot.Total, snapshot.Success, snapshot.Failed, snapshot.Skipped)
					printMu.Unlock()
				}
				if scanErr != nil {
					return fmt.Errorf("org scan failed for account %s region %s: %w", acct.ID, region, scanErr)
				}
				return nil
			})
		}
	}
	waitErr := g.Wait()
	if flags.Output != "json" {
		renderFanoutSummary("Org + Region", results)
	}
	return waitErr
}

func runScanWithRetry(
	cfg aws.Config,
	flags model.Flags,
	versionInfo model.VersionInfo,
	storageService storage.Service,
	useSpinner bool,
) error {
	const maxAttempts = 3
	const baseBackoff = 500 * time.Millisecond
	const maxBackoff = 5 * time.Second
	var lastErr error
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := runConfiguredScan(cfg, flags, versionInfo, storageService, useSpinner)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableScanError(err) || attempt == maxAttempts {
			return err
		}
		backoff := retryBackoffDuration(attempt, baseBackoff, maxBackoff, rng)
		if flags.Output != "json" {
			fmt.Printf("  ↻ Retry %d/%d for region %s in %s: %v\n", attempt+1, maxAttempts, flags.Region, backoff.Round(10*time.Millisecond), err)
		}
		time.Sleep(backoff)
	}
	return lastErr
}

func runScanJSONPayloadWithRetry(
	cfg aws.Config,
	flags model.Flags,
	versionInfo model.VersionInfo,
	storageService storage.Service,
) (map[string]interface{}, error) {
	const maxAttempts = 3
	const baseBackoff = 500 * time.Millisecond
	const maxBackoff = 5 * time.Second
	var lastErr error
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		payload, err := runConfiguredScanJSONPayload(cfg, flags, versionInfo, storageService)
		if err == nil {
			return payload, nil
		}
		lastErr = err
		if !isRetryableScanError(err) || attempt == maxAttempts {
			return nil, err
		}
		backoff := retryBackoffDuration(attempt, baseBackoff, maxBackoff, rng)
		time.Sleep(backoff)
	}
	return nil, lastErr
}

func runConfiguredScanJSONPayload(
	awsCfg aws.Config,
	flags model.Flags,
	versionInfo model.VersionInfo,
	storageService storage.Service,
) (payload map[string]interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during security scan for region %s: %v\n%s", flags.Region, r, string(debug.Stack()))
		}
	}()
	if flags.Region == "" {
		flags.Region = awsCfg.Region
	}
	flags.Output = "json"

	orchestratorService := buildOrchestratorService(awsCfg, flags.Output, versionInfo, storageService)
	out, err := orchestratorService.OrchestrateJSON(flags)
	if err != nil {
		return nil, fmt.Errorf("security scan failed for region %s: %w", flags.Region, err)
	}
	return out, nil
}

func retryBackoffDuration(attempt int, base, max time.Duration, rng *rand.Rand) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	if max < base {
		max = base
	}

	backoff := base
	for i := 1; i < attempt; i++ {
		backoff *= 2
		if backoff >= max {
			backoff = max
			break
		}
	}
	jitterBound := backoff / 2
	if jitterBound <= 0 || rng == nil {
		return backoff
	}
	jitter := time.Duration(rng.Int63n(int64(jitterBound) + 1))
	if backoff+jitter > max {
		return max
	}
	return backoff + jitter
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
		accounts = append(accounts, buildActiveOrgAccounts(page.Accounts)...)
	}
	if len(accounts) == 0 {
		return nil, "", fmt.Errorf("no active organization accounts discovered")
	}
	return accounts, managementAccountID, nil
}

func buildActiveOrgAccounts(accounts []orgtypes.Account) []orgAccount {
	out := make([]orgAccount, 0, len(accounts))
	for _, a := range accounts {
		if a.Status != orgtypes.AccountStatusActive {
			continue
		}
		id := aws.ToString(a.Id)
		if id == "" {
			continue
		}
		out = append(out, orgAccount{ID: id, Name: aws.ToString(a.Name)})
	}
	return out
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

func renderFanoutSummary(mode string, results []fanoutScanResult) {
	if len(results) == 0 {
		return
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].AccountID != results[j].AccountID {
			return results[i].AccountID < results[j].AccountID
		}
		if results[i].Region != results[j].Region {
			return results[i].Region < results[j].Region
		}
		return results[i].Status < results[j].Status
	})

	success := 0
	failed := 0
	skipped := 0

	fmt.Printf("\n\n=== Consolidated %s Scan Summary ===\n", mode)
	fmt.Printf("%-14s %-20s %-12s %-8s %-10s %s\n", "ACCOUNT_ID", "ACCOUNT_NAME", "REGION", "STATUS", "DURATION", "ERROR")
	for _, r := range results {
		switch r.Status {
		case "SUCCESS":
			success++
		case "FAILED":
			failed++
		case "SKIPPED":
			skipped++
		}
		duration := "-"
		if r.Duration > 0 {
			duration = r.Duration.Round(10 * time.Millisecond).String()
		}
		accountID := r.AccountID
		if accountID == "" {
			accountID = "-"
		}
		accountName := r.AccountName
		if accountName == "" {
			accountName = "-"
		}
		errText := r.Error
		if errText == "" {
			errText = "-"
		}
		fmt.Printf("%-14s %-20s %-12s %-8s %-10s %s\n", accountID, accountName, r.Region, r.Status, duration, errText)
	}
	fmt.Printf("TOTAL=%d SUCCESS=%d FAILED=%d SKIPPED=%d\n", len(results), success, failed, skipped)

	rollups := buildAccountRollups(results)
	if len(rollups) == 0 {
		return
	}
	fmt.Printf("\nAccount-Level Rollup\n")
	fmt.Printf("%-14s %-20s %-6s %-7s %-6s %-7s\n", "ACCOUNT_ID", "ACCOUNT_NAME", "TOTAL", "SUCCESS", "FAILED", "SKIPPED")
	for _, r := range rollups {
		fmt.Printf("%-14s %-20s %-6d %-7d %-6d %-7d\n", r.AccountID, r.AccountName, r.Total, r.Success, r.Failed, r.Skipped)
	}
}

func buildAccountRollups(results []fanoutScanResult) []accountScanRollup {
	type key struct {
		id   string
		name string
	}
	m := map[key]*accountScanRollup{}
	for _, r := range results {
		if strings.TrimSpace(r.AccountID) == "" {
			continue
		}
		k := key{id: r.AccountID, name: r.AccountName}
		existing, ok := m[k]
		if !ok {
			existing = &accountScanRollup{
				AccountID:   r.AccountID,
				AccountName: r.AccountName,
			}
			m[k] = existing
		}
		existing.Total++
		switch r.Status {
		case "SUCCESS":
			existing.Success++
		case "FAILED":
			existing.Failed++
		case "SKIPPED":
			existing.Skipped++
		}
	}
	out := make([]accountScanRollup, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AccountID < out[j].AccountID })
	return out
}

func updateFanoutProgress(p *fanoutProgress, status string) fanoutProgress {
	if p == nil {
		return fanoutProgress{}
	}
	p.Completed++
	switch status {
	case "SUCCESS":
		p.Success++
	case "FAILED":
		p.Failed++
	case "SKIPPED":
		p.Skipped++
	}
	return *p
}
