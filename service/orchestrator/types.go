package orchestrator

import (
	"github.com/thirukguru/aws-perimeter/model"
	"github.com/thirukguru/aws-perimeter/service/apigateway"
	"github.com/thirukguru/aws-perimeter/service/cloudtrail"
	"github.com/thirukguru/aws-perimeter/service/cloudtrailsecurity"
	"github.com/thirukguru/aws-perimeter/service/config"
	"github.com/thirukguru/aws-perimeter/service/dataprotection"
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
	awssts "github.com/thirukguru/aws-perimeter/service/sts"
	"github.com/thirukguru/aws-perimeter/service/vpc"
	"github.com/thirukguru/aws-perimeter/service/vpcadvanced"
	"github.com/thirukguru/aws-perimeter/service/vpcendpoints"
)

type service struct {
	// Core services
	stsService        awssts.Service
	vpcService        vpc.Service
	iamService        iam.Service
	s3Service         s3security.Service
	cloudtrailService cloudtrail.Service
	secretsService    secrets.Service
	securityhubSvc    securityhub.Service
	guarddutyService  guardduty.Service
	apigatewayService apigateway.Service
	resourcePolSvc    resourcepolicy.Service
	outputService     output.Service
	versionInfo       model.VersionInfo
	// Extended security services
	shieldService        shield.Service
	elbService           elb.Service
	route53Service       route53.Service
	inspectorService     inspector.Service
	lambdaSecService     lambdasecurity.Service
	messagingService     messaging.Service
	cloudtrailSecService cloudtrailsecurity.Service
	configService        config.Service
	dataprotectionSvc    dataprotection.Service
	loggingService       logging.Service
	governanceService    governance.Service
	vpcEndpointsService  vpcendpoints.Service
	vpcAdvancedService   vpcadvanced.Service
	iamAdvancedService   iamadvanced.Service
}

// Service is the interface for orchestrator service.
type Service interface {
	Orchestrate(flags model.Flags) error
}
