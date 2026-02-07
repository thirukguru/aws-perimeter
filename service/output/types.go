package output

import (
	"github.com/thirukguru/aws-perimeter/model"
	extratables "github.com/thirukguru/aws-perimeter/utils/extra_tables"
	iamtable "github.com/thirukguru/aws-perimeter/utils/iam_table"
	jsonoutput "github.com/thirukguru/aws-perimeter/utils/json_output"
	securitytable "github.com/thirukguru/aws-perimeter/utils/security_table"
	"github.com/thirukguru/aws-perimeter/utils/spinner"
)

// Format represents the output format type
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatHTML  Format = "html"
)

// Renderer defines the interface for drawing tables
type Renderer interface {
	DrawSecurityTable(input model.RenderSecurityInput)
	DrawIAMTable(input model.RenderIAMInput)
	DrawS3Table(input model.RenderS3Input)
	DrawCloudTrailTable(input model.RenderCloudTrailInput)
	DrawSecretsTable(input model.RenderSecretsInput)
	DrawAdvancedTable(input model.RenderAdvancedInput)
	OutputSecurityJSON(input model.RenderSecurityInput) error
	OutputIAMJSON(input model.RenderIAMInput) error
	OutputS3JSON(input model.RenderS3Input) error
	OutputCloudTrailJSON(input model.RenderCloudTrailInput) error
	OutputSecretsJSON(input model.RenderSecretsInput) error
	OutputAdvancedJSON(input model.RenderAdvancedInput) error
	StopSpinner()
}

type realRenderer struct{}

func (r *realRenderer) DrawSecurityTable(input model.RenderSecurityInput) {
	securitytable.DrawSecurityTable(input)
}

func (r *realRenderer) DrawIAMTable(input model.RenderIAMInput) {
	iamtable.DrawIAMTable(input)
}

func (r *realRenderer) DrawS3Table(input model.RenderS3Input) {
	extratables.DrawS3Table(input)
}

func (r *realRenderer) DrawCloudTrailTable(input model.RenderCloudTrailInput) {
	extratables.DrawCloudTrailTable(input)
}

func (r *realRenderer) DrawSecretsTable(input model.RenderSecretsInput) {
	extratables.DrawSecretsTable(input)
}

func (r *realRenderer) DrawAdvancedTable(input model.RenderAdvancedInput) {
	extratables.DrawAdvancedTable(input)
}

func (r *realRenderer) OutputSecurityJSON(input model.RenderSecurityInput) error {
	return jsonoutput.OutputSecurityJSON(input)
}

func (r *realRenderer) OutputIAMJSON(input model.RenderIAMInput) error {
	return jsonoutput.OutputIAMJSON(input)
}

func (r *realRenderer) OutputS3JSON(input model.RenderS3Input) error {
	return jsonoutput.OutputS3JSON(input)
}

func (r *realRenderer) OutputCloudTrailJSON(input model.RenderCloudTrailInput) error {
	return jsonoutput.OutputCloudTrailJSON(input)
}

func (r *realRenderer) OutputSecretsJSON(input model.RenderSecretsInput) error {
	return jsonoutput.OutputSecretsJSON(input)
}

func (r *realRenderer) OutputAdvancedJSON(input model.RenderAdvancedInput) error {
	return jsonoutput.OutputAdvancedJSON(input)
}

func (r *realRenderer) StopSpinner() {
	spinner.StopSpinner()
}

// service is the internal implementation
type service struct {
	format   Format
	renderer Renderer
}

// Service defines the interface for output operations
type Service interface {
	RenderSecurity(input model.RenderSecurityInput) error
	RenderIAM(input model.RenderIAMInput) error
	RenderS3(input model.RenderS3Input) error
	RenderCloudTrail(input model.RenderCloudTrailInput) error
	RenderSecrets(input model.RenderSecretsInput) error
	RenderAdvanced(input model.RenderAdvancedInput) error
	StopSpinner()
}
