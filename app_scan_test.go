package main

import (
	"errors"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/thirukguru/aws-perimeter/model"
	"github.com/thirukguru/aws-perimeter/service/storage"
)

func TestDedupeRegions(t *testing.T) {
	in := []string{"us-east-1", " us-east-1 ", "", "us-west-2", "us-west-2"}
	got := dedupeRegions(in)
	if len(got) != 2 || got[0] != "us-east-1" || got[1] != "us-west-2" {
		t.Fatalf("unexpected dedupe result: %v", got)
	}
}

func TestResolveRegionsFromConfig_ExplicitRegions(t *testing.T) {
	flags := model.Flags{Regions: []string{"us-east-1", "us-west-2", "us-east-1"}}
	got, err := resolveRegionsFromConfig(flags, aws.Config{Region: "eu-west-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "us-east-1" || got[1] != "us-west-2" {
		t.Fatalf("unexpected regions: %v", got)
	}
}

func TestResolveRegionsFromConfig_Fallbacks(t *testing.T) {
	got, err := resolveRegionsFromConfig(model.Flags{Region: "ap-south-1"}, aws.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "ap-south-1" {
		t.Fatalf("unexpected regions: %v", got)
	}

	got, err = resolveRegionsFromConfig(model.Flags{}, aws.Config{Region: "us-east-2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "us-east-2" {
		t.Fatalf("unexpected regions: %v", got)
	}
}

func TestResolveRegionsFromConfig_ErrorWhenNoRegion(t *testing.T) {
	_, err := resolveRegionsFromConfig(model.Flags{}, aws.Config{})
	if err == nil {
		t.Fatalf("expected error when no region information is available")
	}
}

func TestIsRetryableScanError(t *testing.T) {
	if !isRetryableScanError(errors.New("RequestLimitExceeded: throttling")) {
		t.Fatalf("expected throttling error to be retryable")
	}
	if isRetryableScanError(errors.New("validation failed")) {
		t.Fatalf("expected validation error to be non-retryable")
	}
}

func TestBuildActiveOrgAccounts(t *testing.T) {
	got := buildActiveOrgAccounts([]orgtypes.Account{
		{Id: aws.String("111111111111"), Name: aws.String("active-1"), Status: orgtypes.AccountStatusActive},
		{Id: aws.String(""), Name: aws.String("missing-id"), Status: orgtypes.AccountStatusActive},
		{Id: aws.String("222222222222"), Name: aws.String("suspended"), Status: orgtypes.AccountStatusSuspended},
		{Id: aws.String("333333333333"), Name: aws.String("active-2"), Status: orgtypes.AccountStatusActive},
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 active accounts, got %d", len(got))
	}
	if got[0].ID != "111111111111" || got[1].ID != "333333333333" {
		t.Fatalf("unexpected active account set: %+v", got)
	}
}

func TestRunOrgScansWithConfig_SkipsAssumeRoleErrors(t *testing.T) {
	var scanCalls int32
	err := runOrgScansWithConfig(
		aws.Config{Region: "us-east-1"},
		model.Flags{MaxParallel: 2, OrgRoleName: "AuditRole"},
		model.VersionInfo{},
		nil,
		orgScanDeps{
			listAccounts: func(aws.Config) ([]orgAccount, string, error) {
				return []orgAccount{
					{ID: "111111111111", Name: "mgmt"},
					{ID: "222222222222", Name: "member"},
				}, "111111111111", nil
			},
			resolveRegions: func(model.Flags, aws.Config) ([]string, error) {
				return []string{"us-east-1"}, nil
			},
			assumeRole: func(aws.Config, string, string, string, string) (aws.Config, error) {
				return aws.Config{}, errors.New("assume denied")
			},
			runScan: func(aws.Config, model.Flags, model.VersionInfo, storage.Service, bool) error {
				atomic.AddInt32(&scanCalls, 1)
				return nil
			},
		},
	)
	if err != nil {
		t.Fatalf("expected no error when member account assume role fails, got: %v", err)
	}
	if got := atomic.LoadInt32(&scanCalls); got != 1 {
		t.Fatalf("expected only management account scan to run, got %d", got)
	}
}

func TestRunOrgScansWithConfig_ReturnsErrorOnScanFailure(t *testing.T) {
	err := runOrgScansWithConfig(
		aws.Config{Region: "us-east-1"},
		model.Flags{MaxParallel: 1},
		model.VersionInfo{},
		nil,
		orgScanDeps{
			listAccounts: func(aws.Config) ([]orgAccount, string, error) {
				return []orgAccount{{ID: "111111111111", Name: "mgmt"}}, "111111111111", nil
			},
			resolveRegions: func(model.Flags, aws.Config) ([]string, error) {
				return []string{"us-west-2"}, nil
			},
			assumeRole: func(aws.Config, string, string, string, string) (aws.Config, error) {
				return aws.Config{}, nil
			},
			runScan: func(aws.Config, model.Flags, model.VersionInfo, storage.Service, bool) error {
				return errors.New("throttling not recovered")
			},
		},
	)
	if err == nil {
		t.Fatalf("expected org scan error")
	}
	if !strings.Contains(err.Error(), "org scan failed for account 111111111111 region us-west-2") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRunMultiRegionScansWithConfig_RespectsMaxParallel(t *testing.T) {
	var inFlight int32
	var maxInFlight int32
	var calls int32
	var mu sync.Mutex
	regionsSeen := map[string]bool{}

	deps := multiRegionScanDeps{
		resolveRegions: func(model.Flags, aws.Config) ([]string, error) {
			return []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1"}, nil
		},
		runScan: func(_ aws.Config, flags model.Flags, _ model.VersionInfo, _ storage.Service, _ bool) error {
			cur := atomic.AddInt32(&inFlight, 1)
			defer atomic.AddInt32(&inFlight, -1)
			for {
				prev := atomic.LoadInt32(&maxInFlight)
				if cur <= prev || atomic.CompareAndSwapInt32(&maxInFlight, prev, cur) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			atomic.AddInt32(&calls, 1)
			mu.Lock()
			regionsSeen[flags.Region] = true
			mu.Unlock()
			return nil
		},
	}

	err := runMultiRegionScansWithConfig(
		aws.Config{Region: "us-east-1"},
		model.Flags{MaxParallel: 2},
		model.VersionInfo{},
		nil,
		deps,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(&maxInFlight); got > 2 {
		t.Fatalf("max in-flight scans exceeded limit: got %d want <= 2", got)
	}
	if got := atomic.LoadInt32(&calls); got != 5 {
		t.Fatalf("expected 5 scans, got %d", got)
	}
	for _, r := range []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1"} {
		if !regionsSeen[r] {
			t.Fatalf("missing region scan for %s", r)
		}
	}
}

func TestRunOrgScansWithConfig_RespectsMaxParallel(t *testing.T) {
	var inFlight int32
	var maxInFlight int32
	var calls int32

	err := runOrgScansWithConfig(
		aws.Config{Region: "us-east-1"},
		model.Flags{MaxParallel: 3},
		model.VersionInfo{},
		nil,
		orgScanDeps{
			listAccounts: func(aws.Config) ([]orgAccount, string, error) {
				return []orgAccount{
					{ID: "111111111111", Name: "mgmt"},
					{ID: "222222222222", Name: "member-1"},
					{ID: "333333333333", Name: "member-2"},
				}, "111111111111", nil
			},
			resolveRegions: func(model.Flags, aws.Config) ([]string, error) {
				return []string{"us-east-1", "us-west-2"}, nil
			},
			assumeRole: func(base aws.Config, accountID, region, roleName, externalID string) (aws.Config, error) {
				return aws.Config{Region: region}, nil
			},
			runScan: func(_ aws.Config, _ model.Flags, _ model.VersionInfo, _ storage.Service, _ bool) error {
				cur := atomic.AddInt32(&inFlight, 1)
				defer atomic.AddInt32(&inFlight, -1)
				for {
					prev := atomic.LoadInt32(&maxInFlight)
					if cur <= prev || atomic.CompareAndSwapInt32(&maxInFlight, prev, cur) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				atomic.AddInt32(&calls, 1)
				return nil
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := atomic.LoadInt32(&maxInFlight); got > 3 {
		t.Fatalf("max in-flight scans exceeded limit: got %d want <= 3", got)
	}
	if got := atomic.LoadInt32(&calls); got != 6 {
		t.Fatalf("expected 6 account/region scans, got %d", got)
	}
}

func TestRunMultiRegionScansWithConfig_PropagatesScanError(t *testing.T) {
	wantErr := "scan failed in us-west-2"
	err := runMultiRegionScansWithConfig(
		aws.Config{Region: "us-east-1"},
		model.Flags{MaxParallel: 2},
		model.VersionInfo{},
		nil,
		multiRegionScanDeps{
			resolveRegions: func(model.Flags, aws.Config) ([]string, error) {
				return []string{"us-east-1", "us-west-2"}, nil
			},
			runScan: func(_ aws.Config, flags model.Flags, _ model.VersionInfo, _ storage.Service, _ bool) error {
				if flags.Region == "us-west-2" {
					return errors.New(wantErr)
				}
				return nil
			},
		},
	)
	if err == nil {
		t.Fatalf("expected error from region scan")
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunMultiRegionScansWithConfig_BestEffortReturnsNilWhenAnyRegionSucceeds(t *testing.T) {
	err := runMultiRegionScansWithConfig(
		aws.Config{Region: "us-east-1"},
		model.Flags{MaxParallel: 2, BestEffort: true},
		model.VersionInfo{},
		nil,
		multiRegionScanDeps{
			resolveRegions: func(model.Flags, aws.Config) ([]string, error) {
				return []string{"us-east-1", "us-west-2"}, nil
			},
			runScan: func(_ aws.Config, flags model.Flags, _ model.VersionInfo, _ storage.Service, _ bool) error {
				if flags.Region == "us-west-2" {
					return errors.New("temporary DNS failure")
				}
				return nil
			},
		},
	)
	if err != nil {
		t.Fatalf("expected nil error in best-effort mode when one region succeeds, got: %v", err)
	}
}

func TestRunMultiRegionScansWithConfig_BestEffortStillFailsWhenAllRegionsFail(t *testing.T) {
	err := runMultiRegionScansWithConfig(
		aws.Config{Region: "us-east-1"},
		model.Flags{MaxParallel: 2, BestEffort: true},
		model.VersionInfo{},
		nil,
		multiRegionScanDeps{
			resolveRegions: func(model.Flags, aws.Config) ([]string, error) {
				return []string{"us-east-1", "us-west-2"}, nil
			},
			runScan: func(_ aws.Config, _ model.Flags, _ model.VersionInfo, _ storage.Service, _ bool) error {
				return errors.New("all regions failed")
			},
		},
	)
	if err == nil {
		t.Fatalf("expected error when all regions fail, even in best-effort mode")
	}
}

func TestFormatMultiRegionFailure(t *testing.T) {
	msg := formatMultiRegionFailure(errors.New("lookup timeout"))
	if !strings.Contains(msg, "Try again after sometime.") {
		t.Fatalf("missing retry hint in failure message: %s", msg)
	}
	if !strings.Contains(msg, "lookup timeout") {
		t.Fatalf("missing original error in failure message: %s", msg)
	}
}

func TestBuildFanoutOutputFile(t *testing.T) {
	ts := time.Date(2026, 2, 10, 21, 30, 45, 0, time.UTC)

	got := buildFanoutOutputFile("reports/security-report.html", "", "us-east-1", ts)
	if got != "reports/security-report-us-east-1-20260210-213045.html" {
		t.Fatalf("unexpected multi-region output file: %s", got)
	}

	got = buildFanoutOutputFile("reports/security-report.html", "123456789012", "us-west-2", ts)
	if got != "reports/security-report-123456789012-us-west-2-20260210-213045.html" {
		t.Fatalf("unexpected org-scan output file: %s", got)
	}

	got = buildFanoutOutputFile("security-report.html", "", "eu-west-1", ts)
	if got != "security-report-eu-west-1-20260210-213045.html" {
		t.Fatalf("unexpected relative output file: %s", got)
	}
}

func TestBuildAccountRollups(t *testing.T) {
	rollups := buildAccountRollups([]fanoutScanResult{
		{AccountID: "111111111111", AccountName: "mgmt", Region: "us-east-1", Status: "SUCCESS"},
		{AccountID: "111111111111", AccountName: "mgmt", Region: "us-west-2", Status: "FAILED"},
		{AccountID: "222222222222", AccountName: "dev", Region: "us-east-1", Status: "SKIPPED"},
		{AccountID: "222222222222", AccountName: "dev", Region: "us-west-2", Status: "SUCCESS"},
		{AccountID: "", AccountName: "", Region: "us-east-1", Status: "SUCCESS"},
	})

	if len(rollups) != 2 {
		t.Fatalf("expected 2 account rollups, got %d", len(rollups))
	}
	if rollups[0].AccountID != "111111111111" || rollups[0].Total != 2 || rollups[0].Success != 1 || rollups[0].Failed != 1 || rollups[0].Skipped != 0 {
		t.Fatalf("unexpected rollup[0]: %+v", rollups[0])
	}
	if rollups[1].AccountID != "222222222222" || rollups[1].Total != 2 || rollups[1].Success != 1 || rollups[1].Failed != 0 || rollups[1].Skipped != 1 {
		t.Fatalf("unexpected rollup[1]: %+v", rollups[1])
	}
}

func TestBuildAccountRollups_EmptyWhenNoAccountIDs(t *testing.T) {
	rollups := buildAccountRollups([]fanoutScanResult{
		{Region: "us-east-1", Status: "SUCCESS"},
		{Region: "us-west-2", Status: "FAILED"},
	})
	if len(rollups) != 0 {
		t.Fatalf("expected empty rollups, got %+v", rollups)
	}
}

func TestUpdateFanoutProgress(t *testing.T) {
	p := &fanoutProgress{Total: 3}
	s1 := updateFanoutProgress(p, "SUCCESS")
	if s1.Completed != 1 || s1.Success != 1 || s1.Failed != 0 || s1.Skipped != 0 {
		t.Fatalf("unexpected snapshot after success: %+v", s1)
	}

	s2 := updateFanoutProgress(p, "FAILED")
	if s2.Completed != 2 || s2.Success != 1 || s2.Failed != 1 || s2.Skipped != 0 {
		t.Fatalf("unexpected snapshot after failure: %+v", s2)
	}

	s3 := updateFanoutProgress(p, "SKIPPED")
	if s3.Completed != 3 || s3.Success != 1 || s3.Failed != 1 || s3.Skipped != 1 || s3.Total != 3 {
		t.Fatalf("unexpected snapshot after skip: %+v", s3)
	}
}

func TestRetryBackoffDuration_BoundsAndCap(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	base := 500 * time.Millisecond
	max := 5 * time.Second

	d1 := retryBackoffDuration(1, base, max, rng)
	if d1 < base || d1 > base+base/2 {
		t.Fatalf("attempt 1 backoff out of bounds: %s", d1)
	}

	d2 := retryBackoffDuration(2, base, max, rng)
	if d2 < 1*time.Second || d2 > 1500*time.Millisecond {
		t.Fatalf("attempt 2 backoff out of bounds: %s", d2)
	}

	d4 := retryBackoffDuration(4, base, max, rng)
	if d4 < 4*time.Second || d4 > max {
		t.Fatalf("attempt 4 backoff out of bounds/cap: %s", d4)
	}

	d10 := retryBackoffDuration(10, base, max, rng)
	if d10 > max {
		t.Fatalf("attempt 10 should be capped at %s, got %s", max, d10)
	}
}
