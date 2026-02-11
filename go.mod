module github.com/thirukguru/aws-perimeter

go 1.24.6

require (
	github.com/aws/aws-sdk-go-v2 v1.41.1
	github.com/aws/aws-sdk-go-v2/config v1.31.6
	github.com/aws/aws-sdk-go-v2/credentials v1.18.10
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.45.8
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.38.4
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.33.5
	github.com/aws/aws-sdk-go-v2/service/backup v1.54.6
	github.com/aws/aws-sdk-go-v2/service/bedrock v1.53.2
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.60.0
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.55.5
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.53.1
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.63.1
	github.com/aws/aws-sdk-go-v2/service/configservice v1.61.0
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.55.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.279.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.53.0
	github.com/aws/aws-sdk-go-v2/service/ecs v1.71.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.77.1
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.54.6
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.73.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.53.2
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.46.2
	github.com/aws/aws-sdk-go-v2/service/kms v1.49.5
	github.com/aws/aws-sdk-go-v2/service/lambda v1.88.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.50.2
	github.com/aws/aws-sdk-go-v2/service/rds v1.114.0
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.31.6
	github.com/aws/aws-sdk-go-v2/service/route53 v1.62.1
	github.com/aws/aws-sdk-go-v2/service/s3 v1.96.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.1
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.67.3
	github.com/aws/aws-sdk-go-v2/service/ses v1.34.18
	github.com/aws/aws-sdk-go-v2/service/shield v1.34.17
	github.com/aws/aws-sdk-go-v2/service/sns v1.39.11
	github.com/aws/aws-sdk-go-v2/service/sqs v1.42.21
	github.com/aws/aws-sdk-go-v2/service/sts v1.38.2
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.70.7
	github.com/briandowns/spinner v1.23.2
	github.com/jedib0t/go-pretty/v6 v6.6.8
	github.com/spf13/pflag v1.0.10
	github.com/stretchr/testify v1.11.1
	golang.org/x/sync v0.17.0
	golang.org/x/sys v0.37.0
	golang.org/x/term v0.29.0
	modernc.org/sqlite v1.45.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.4 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.58.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.51.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.45.18 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.11.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/memorydb v1.33.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/redshift v1.62.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sfn v1.40.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.29.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.34.2 // indirect
	github.com/aws/smithy-go v1.24.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-colorable v0.1.2 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/text v0.22.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
