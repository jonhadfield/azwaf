package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"

	"github.com/jonhadfield/findexec"

	"github.com/jonhadfield/azwaf/helpers"
	"github.com/jonhadfield/azwaf/logging"
)

func compare(original interface{}, updated []byte) (differencesFound bool, err error) {
	funcName := helpers.GetFunctionName()

	logging.Debugf("%s | finding differences between the current policy version and the proposed", funcName)

	origJSON, err := marshalJSON(original)
	if err != nil {
		return false, err
	}

	newJSON, err := marshalJSON(updated)
	if err != nil {
		return false, err
	}

	// identical input needs no temporary files and no diff process
	if bytes.Equal(origJSON, newJSON) {
		return false, nil
	}

	if _, err = diffTempFiles(origJSON, newJSON); err != nil {
		return false, err
	}

	return true, nil
}

// diffTempFiles writes both sides to temporary files and runs diff -u over
// them, returning its output and removing the files before it returns.
//
// compare and DisplayStringDiffWithDiffTool had a copy of this each. They still
// differ in what they do with the result: compare only wants to know whether
// there was one, and prints nothing.
func diffTempFiles(orig, updated []byte) ([]byte, error) {
	diffBinary := findexec.Find("diff", "")
	if diffBinary == "" {
		return nil, errors.New("failed to find compare binary")
	}

	f1, err := writeTempFile(orig)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = os.Remove(f1)
	}()

	f2, err := writeTempFile(updated)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = os.Remove(f2)
	}()

	out, exitCode, err := runDiff(diffBinary, f1, f2)
	if err != nil {
		return nil, err
	}

	if exitCode == diffErrorExitCode {
		return nil, fmt.Errorf("failed to compare: '%s' with '%s'", f1, f2)
	}

	return out, nil
}

func marshalJSON(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case []byte:
		var out interface{}
		if err := json.Unmarshal(val, &out); err != nil {
			return nil, err
		}
		return json.MarshalIndent(out, "", "  ")
	case *armfrontdoor.WebApplicationFirewallPolicy:
		return json.MarshalIndent(val, "", "  ")
	default:
		return nil, errors.New("unexpected type")
	}
}

func writeTempFile(data []byte) (string, error) {
	f, err := os.CreateTemp("", "waf-afd-policy-")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// runDiff runs diff -u and returns its output alongside the exit code. diff
// exits 1 when the files differ, which is not an error.
func runDiff(binary, f1, f2 string) (out []byte, exitCode int, err error) {
	// #nosec
	cmd := exec.Command(binary, "-u", f1, f2)

	out, err = cmd.CombinedOutput()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return out, exitError.ExitCode(), nil
		}

		// anything that is not an exit status is a real failure to run diff
		return nil, 0, err
	}

	return out, 0, nil
}
