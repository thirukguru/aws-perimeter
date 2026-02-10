package main

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/thirukguru/aws-perimeter/model"
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
