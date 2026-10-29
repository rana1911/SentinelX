// Harness integrity: the model is only allowed to author text strictly
// between the MODEL_BEGIN and MODEL_END markers. Everything else in the
// final test file — setUp(), test_exploit(), the success assertion — must
// match what the fixed template produced. Without this, a model could
// rewrite the assertion line itself (e.g. weaken assertGt into a no-op) and
// every other check in this package would then be validating the wrong
// thing.
package verify

import (
	"errors"
	"fmt"
	"strings"
)

const (
	ModelBeginMarker = "// MODEL_BEGIN"
	ModelEndMarker   = "// MODEL_END"
)

// ErrMarkers indicates the marker structure is malformed (missing, out of
// order, or duplicated) — treated as a hard failure, since we can no longer
// tell harness code from model code.
var ErrMarkers = errors.New("verify: MODEL_BEGIN/MODEL_END markers malformed")

// SplitModelRegion returns (prefix, modelRegion, suffix) of a rendered test
// file, split at the markers. It errors unless exactly one MODEL_BEGIN
// precedes exactly one MODEL_END.
func SplitModelRegion(file string) (prefix, region, suffix string, err error) {
	if strings.Count(file, ModelBeginMarker) != 1 || strings.Count(file, ModelEndMarker) != 1 {
		return "", "", "", ErrMarkers
	}
	bi := strings.Index(file, ModelBeginMarker)
	ei := strings.Index(file, ModelEndMarker)
	if bi > ei {
		return "", "", "", ErrMarkers
	}
	prefix = file[:bi+len(ModelBeginMarker)]
	region = file[bi+len(ModelBeginMarker) : ei]
	suffix = file[ei:]
	return prefix, region, suffix, nil
}

// CheckHarnessIntegrity confirms that the fixed (non-model) parts of the
// rendered test file are identical to the fixed parts of the original
// template. rendered is the final file sent to forge; templateRendered is
// the same template rendered with the SAME substitutions but an empty model
// region. Any difference outside the marker region means the model edited
// harness code it was not permitted to touch.
func CheckHarnessIntegrity(rendered, templateRendered string) error {
	rPre, _, rSuf, err := SplitModelRegion(rendered)
	if err != nil {
		return fmt.Errorf("rendered file: %w", err)
	}
	tPre, _, tSuf, err := SplitModelRegion(templateRendered)
	if err != nil {
		return fmt.Errorf("template: %w", err)
	}
	if rPre != tPre {
		return fmt.Errorf("verify: harness code BEFORE the model region was modified (the model may not edit setUp/imports/contract header)")
	}
	if rSuf != tSuf {
		return fmt.Errorf("verify: harness code AFTER the model region was modified (the model may not edit the success assertion or test_exploit body)")
	}
	return nil
}

// ModelRegion extracts just the model-authored text from a rendered file,
// for passing to the source-level cheat guard (CheckSource). This ensures
// the source scan runs on exactly the model's code, not the harness lines
// (which legitimately contain vm.* calls).
func ModelRegion(file string) (string, error) {
	_, region, _, err := SplitModelRegion(file)
	return region, err
}
