package lambdasecurity

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

func TestReservedConcurrencyIsZero(t *testing.T) {
	if !reservedConcurrencyIsZero(aws.Int32(0)) {
		t.Fatalf("expected reserved concurrency=0 to be flagged")
	}

	if reservedConcurrencyIsZero(aws.Int32(2)) {
		t.Fatalf("did not expect reserved concurrency>0 to be flagged")
	}
}

func TestHasRiskyVPCConfig(t *testing.T) {
	fn := lambdatypes.FunctionConfiguration{
		VpcConfig: &lambdatypes.VpcConfigResponse{
			SubnetIds: []string{"subnet-a", "subnet-b"},
		},
	}

	if !hasRiskyVPCConfig(fn, map[string]bool{}, map[string]bool{}) {
		t.Fatalf("expected risky VPC config when no NAT/endpoints exist")
	}

	if hasRiskyVPCConfig(fn, map[string]bool{"subnet-a": true}, map[string]bool{}) {
		t.Fatalf("did not expect risk when at least one subnet has NAT")
	}

	if hasRiskyVPCConfig(fn, map[string]bool{}, map[string]bool{"subnet-b": true}) {
		t.Fatalf("did not expect risk when at least one subnet has VPC endpoint")
	}
}

func TestHasSnapStartWithSecretLikeEnv(t *testing.T) {
	snapEnabled := &lambdatypes.SnapStartResponse{ApplyOn: lambdatypes.SnapStartApplyOnPublishedVersions}
	envWithSecrets := &lambdatypes.EnvironmentResponse{
		Variables: map[string]string{
			"DB_PASSWORD": "test",
		},
	}
	if !hasSnapStartWithSecretLikeEnv(snapEnabled, envWithSecrets) {
		t.Fatalf("expected snapstart + secret-like env key to be flagged")
	}

	snapDisabled := &lambdatypes.SnapStartResponse{ApplyOn: lambdatypes.SnapStartApplyOnNone}
	if hasSnapStartWithSecretLikeEnv(snapDisabled, envWithSecrets) {
		t.Fatalf("did not expect snapstart risk when apply_on is none")
	}
}

func TestLooksLikeSecretKeyName(t *testing.T) {
	if !looksLikeSecretKeyName("API_TOKEN") {
		t.Fatalf("expected API_TOKEN to match secret indicator")
	}
	if looksLikeSecretKeyName("LOG_LEVEL") {
		t.Fatalf("did not expect LOG_LEVEL to match secret indicator")
	}
}

func TestUntrustedLayerARNs(t *testing.T) {
	layers := []lambdatypes.Layer{
		{Arn: aws.String("arn:aws:lambda:us-east-1:580247275435:layer:LambdaInsightsExtension:1")},
		{Arn: aws.String("arn:aws:lambda:us-east-1:123456789012:layer:custom-team-layer:3")},
		{Arn: aws.String("arn:aws:lambda:us-east-1:017000801446:layer:AWSLambdaPowertoolsPython:1")},
	}

	got := untrustedLayerARNs(layers)
	if len(got) != 1 {
		t.Fatalf("expected 1 untrusted layer, got %d", len(got))
	}
	if got[0] != "arn:aws:lambda:us-east-1:123456789012:layer:custom-team-layer:3" {
		t.Fatalf("unexpected untrusted layer %q", got[0])
	}
}

func TestIsUnauthenticatedFunctionURL(t *testing.T) {
	if !isUnauthenticatedFunctionURL(lambdatypes.FunctionUrlAuthTypeNone) {
		t.Fatalf("expected auth type NONE to be unauthenticated")
	}
	if isUnauthenticatedFunctionURL(lambdatypes.FunctionUrlAuthTypeAwsIam) {
		t.Fatalf("did not expect AWS_IAM auth type to be unauthenticated")
	}
}

func TestRouteTableHasNATRoute(t *testing.T) {
	if !routeTableHasNATRoute([]ec2types.Route{{NatGatewayId: aws.String("nat-123")}}) {
		t.Fatalf("expected NAT gateway route to be detected")
	}
	if !routeTableHasNATRoute([]ec2types.Route{{InstanceId: aws.String("i-123")}}) {
		t.Fatalf("expected NAT instance route to be detected")
	}
	if routeTableHasNATRoute([]ec2types.Route{{GatewayId: aws.String("igw-123")}}) {
		t.Fatalf("did not expect IGW-only route to be treated as NAT")
	}
}
