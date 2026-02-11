// Package output provides a service for rendering results to the console.
package output

import (
	"github.com/thirukguru/aws-perimeter/model"
)

// NewService creates a new output service with the specified format
func NewService(format string) Service {
	f := FormatTable
	switch format {
	case "json":
		f = FormatJSON
	case "html":
		f = FormatHTML
	}

	return &service{
		format:   f,
		renderer: &realRenderer{},
	}
}

func (s *service) RenderSecurity(input model.RenderSecurityInput) error {
	if s.format == FormatJSON {
		return s.renderer.OutputSecurityJSON(input)
	}
	s.renderer.DrawSecurityTable(input)
	return nil
}

func (s *service) RenderIAM(input model.RenderIAMInput) error {
	if s.format == FormatJSON {
		return s.renderer.OutputIAMJSON(input)
	}
	s.renderer.DrawIAMTable(input)
	return nil
}

func (s *service) RenderS3(input model.RenderS3Input) error {
	if s.format == FormatJSON {
		return s.renderer.OutputS3JSON(input)
	}
	s.renderer.DrawS3Table(input)
	return nil
}

func (s *service) RenderCloudTrail(input model.RenderCloudTrailInput) error {
	if s.format == FormatJSON {
		return s.renderer.OutputCloudTrailJSON(input)
	}
	s.renderer.DrawCloudTrailTable(input)
	return nil
}

func (s *service) RenderSecrets(input model.RenderSecretsInput) error {
	if s.format == FormatJSON {
		return s.renderer.OutputSecretsJSON(input)
	}
	s.renderer.DrawSecretsTable(input)
	return nil
}

func (s *service) RenderAdvanced(input model.RenderAdvancedInput) error {
	if s.format == FormatJSON {
		return s.renderer.OutputAdvancedJSON(input)
	}
	s.renderer.DrawAdvancedTable(input)
	return nil
}

func (s *service) StopSpinner() {
	s.renderer.StopSpinner()
}
