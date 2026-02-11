package vpcadvanced

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestIsInternetRouteViaIGW(t *testing.T) {
	tests := []struct {
		name string
		in   types.Route
		want bool
	}{
		{
			name: "ipv4 default via igw",
			in: types.Route{
				GatewayId:            aws.String("igw-123"),
				DestinationCidrBlock: aws.String("0.0.0.0/0"),
			},
			want: true,
		},
		{
			name: "ipv6 default via igw",
			in: types.Route{
				GatewayId:                aws.String("igw-456"),
				DestinationIpv6CidrBlock: aws.String("::/0"),
			},
			want: true,
		},
		{
			name: "default route via nat is not igw",
			in: types.Route{
				GatewayId:            aws.String("nat-123"),
				DestinationCidrBlock: aws.String("0.0.0.0/0"),
			},
			want: false,
		},
		{
			name: "igw non-default route",
			in: types.Route{
				GatewayId:            aws.String("igw-123"),
				DestinationCidrBlock: aws.String("10.0.0.0/16"),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		if got := isInternetRouteViaIGW(tt.in); got != tt.want {
			t.Fatalf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCIDRsOverlap(t *testing.T) {
	if !cidrsOverlap("10.0.0.0/16", "10.0.1.0/24") {
		t.Fatalf("expected overlapping CIDRs to be detected")
	}
	if cidrsOverlap("10.0.0.0/16", "172.16.0.0/16") {
		t.Fatalf("did not expect non-overlapping private ranges to match in simplified check")
	}
}
