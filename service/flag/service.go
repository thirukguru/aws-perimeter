package flag

import (
	"github.com/spf13/pflag"
	"github.com/thirukguru/aws-perimeter/model"
)

// NewService creates a new flag service.
func NewService() Service {
	return &service{}
}

// GetParsedFlags parses and returns the command-line flags.
func (s *service) GetParsedFlags() (model.Flags, error) {
	profile := pflag.StringP("profile", "p", "", "AWS profile to use")
	region := pflag.StringP("region", "r", "", "AWS region to use")
	version := pflag.BoolP("version", "v", false, "Show version information")
	output := pflag.StringP("output", "o", "table", "Output format (table, json, or html)")
	outputFile := pflag.StringP("output-file", "f", "", "Output file path (required for html format)")

	pflag.Parse()

	flags := model.Flags{
		Profile:    *profile,
		Region:     *region,
		Version:    *version,
		Output:     *output,
		OutputFile: *outputFile,
	}

	return flags, nil
}
