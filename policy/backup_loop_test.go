package policy

// Regression tests for the backup loop semantics: fail-fast must process
// every policy until the first error (it previously stopped after the first
// policy unconditionally), and fail-slow must continue past errors.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func wrappedFDPolicyForLoopTest(name string) WrappedPolicy {
	return WrappedPolicy{
		SubscriptionID: azfakesSubID,
		ResourceGroup:  "rg-one",
		Name:           name,
		Policy:         fdPolicyForFakeTest(),
	}
}

func wrappedAppGWPolicyForLoopTest(name string) WrappedAppGWPolicy {
	return WrappedAppGWPolicy{
		SubscriptionID: azfakesSubID,
		ResourceGroup:  "rg-one",
		Name:           name,
		Policy:         newAppGWPolicyForTest(),
	}
}

func TestBackupPoliciesLoopFailFastBacksUpEveryPolicy(t *testing.T) {
	dir := t.TempDir()
	policies := []WrappedPolicy{
		wrappedFDPolicyForLoopTest("fd-one"),
		wrappedFDPolicyForLoopTest("fd-two"),
	}

	// regression: the loop previously returned after the FIRST policy even on
	// success, silently skipping the rest under --fail-fast
	require.NoError(t, backupPolicies(policies, BackupDestination{Path: dir, FailFast: true, Quiet: true}))

	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 2)

	// each new backup must be tagged with its WAF type for restore dispatch
	data, err := os.ReadFile(filepath.Join(dir, files[0].Name()))
	require.NoError(t, err)

	var peek struct{ WAFType string }
	require.NoError(t, json.Unmarshal(data, &peek))
	require.Equal(t, WAFTypeFrontDoor, peek.WAFType)
}

func TestBackupPoliciesLoopFailFastReturnsError(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "does", "not", "exist")
	policies := []WrappedPolicy{wrappedFDPolicyForLoopTest("fd-one")}

	err := backupPolicies(policies, BackupDestination{Path: missingDir, FailFast: true, Quiet: true})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create file")
}

func TestBackupPoliciesLoopFailSlowContinuesPastErrors(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "does", "not", "exist")
	policies := []WrappedPolicy{
		wrappedFDPolicyForLoopTest("fd-one"),
		wrappedFDPolicyForLoopTest("fd-two"),
	}

	// fail-slow: errors are logged, every policy is attempted, no error returned
	require.NoError(t, backupPolicies(policies, BackupDestination{Path: missingDir, Quiet: true}))
}

func TestBackupAppGWPoliciesLoopBacksUpEveryPolicy(t *testing.T) {
	dir := t.TempDir()
	policies := []WrappedAppGWPolicy{
		wrappedAppGWPolicyForLoopTest("agw-one"),
		wrappedAppGWPolicyForLoopTest("agw-two"),
	}

	require.NoError(t, backupAppGWPolicies(policies, BackupDestination{Path: dir, FailFast: true, Quiet: true}))

	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 2)

	data, err := os.ReadFile(filepath.Join(dir, files[0].Name()))
	require.NoError(t, err)

	var peek struct{ WAFType string }
	require.NoError(t, json.Unmarshal(data, &peek))
	require.Equal(t, WAFTypeAppGW, peek.WAFType)
}

func TestBackupAppGWPoliciesLoopErrorSemantics(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "does", "not", "exist")
	policies := []WrappedAppGWPolicy{
		wrappedAppGWPolicyForLoopTest("agw-one"),
		wrappedAppGWPolicyForLoopTest("agw-two"),
	}

	// fail-fast surfaces the error
	err := backupAppGWPolicies(policies, BackupDestination{Path: missingDir, FailFast: true, Quiet: true})
	require.Error(t, err)

	// fail-slow logs and continues
	require.NoError(t, backupAppGWPolicies(policies, BackupDestination{Path: missingDir, Quiet: true}))
}
