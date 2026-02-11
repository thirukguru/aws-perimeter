package spinner

import (
	"time"

	sp "github.com/briandowns/spinner"
)

var loader *sp.Spinner

// StartSpinner starts the CLI loading spinner.
func StartSpinner() {
	loader = sp.New(sp.CharSets[11], 100*time.Millisecond)
	loader.Color("yellow") //nolint:errcheck
	loader.Suffix = " Scanning AWS infrastructure for security risks..."
	loader.Start()
}

// StopSpinner stops the CLI loading spinner.
func StopSpinner() {
	if loader != nil {
		loader.Stop()
	}
}
