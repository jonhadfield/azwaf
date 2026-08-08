package policy

// Restore-path tests. RestorePolicies error paths return before any Azure
// call; the flows that do reach Azure run against internal/azfakes.

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/stretchr/testify/require"

	"github.com/jonhadfield/azwaf/internal/azfakes"
)

// --- RestorePolicies input validation and dispatch errors ---

func TestRestorePoliciesErrorsWhenNoBackupsFound(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := RestorePolicies(&RestorePoliciesInput{BackupsPaths: []string{t.TempDir()}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no backup files could be found")
}

func TestRestorePoliciesErrorsWithInvalidTarget(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := RestorePolicies(&RestorePoliciesInput{
		BackupsPaths: []string{"../testfiles/wrapped-policy-one.json"},
		TargetPolicy: "not-a-resource-id",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "is invalid")
}

func TestRestorePoliciesErrorsWithTargetAndMultipleBackups(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := RestorePolicies(&RestorePoliciesInput{
		BackupsPaths: []string{
			"../testfiles/wrapped-policy-one.json",
			"../testfiles/wrapped-appgw-policy-one.json",
		},
		TargetPolicy: azfakes.FrontDoorPolicyID(azfakesSubID, "rg-one", "fd-one"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "more than one backup")
}

func TestRestorePoliciesErrorsWhenTargetTypeMismatchesBackup(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Front Door target, AppGW backup
	err := RestorePolicies(&RestorePoliciesInput{
		BackupsPaths: []string{"../testfiles/wrapped-appgw-policy-one.json"},
		TargetPolicy: azfakes.FrontDoorPolicyID(azfakesSubID, "rg-one", "fd-one"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "target is a Front Door WAF policy but the loaded backup is for Application Gateway")

	// AppGW target, Front Door backup
	err = RestorePolicies(&RestorePoliciesInput{
		BackupsPaths: []string{"../testfiles/wrapped-policy-one.json"},
		TargetPolicy: azfakes.AppGWPolicyID(azfakesSubID, "rg-one", "agw-one"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "target is an Application Gateway WAF policy but the loaded backup is for Front Door")
}

// --- restoreAppGWBackups explicit-target handling ---

func TestRestoreAppGWBackupsRejectsMultipleBackupsForSingleTarget(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	err = restoreAppGWBackups(s, &RestorePoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		TargetPolicy: azfakes.AppGWPolicyID(azfakesSubID, "rg-one", "agw-one"),
	}, []WrappedAppGWPolicy{{Name: "one"}, {Name: "two"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "more than one backup")
}

func TestRestoreAppGWBackupsRejectsHashTarget(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	err = restoreAppGWBackups(s, &RestorePoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		TargetPolicy: "abcd1234",
	}, []WrappedAppGWPolicy{{Name: "one"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a hash")
}

func TestRestoreAppGWBackupsRetargetsToExplicitTarget(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	targetID := st.AddAppGWPolicy("rg-target", "agw-target", newAppGWPolicyForTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	// backup originates from a different policy and carries an older ruleset
	backupPolicy := newAppGWPolicyForTest()
	v31 := "3.1"
	backupPolicy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion = &v31

	backup := WrappedAppGWPolicy{
		SubscriptionID: azfakesSubID,
		ResourceGroup:  "rg-src",
		Name:           "agw-src",
		Policy:         backupPolicy,
		PolicyID:       azfakes.AppGWPolicyID(azfakesSubID, "rg-src", "agw-src"),
		WAFType:        WAFTypeAppGW,
	}

	require.NoError(t, restoreAppGWBackups(s, &RestorePoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		TargetPolicy: targetID,
		Force:        true,
	}, []WrappedAppGWPolicy{backup}))

	// the push must land on the target policy, not the backup's origin
	pushed := st.PushedAppGW()
	require.Len(t, pushed, 1)
	require.Equal(t, "agw-target", pushed[0].Name)
	require.Equal(t, "rg-target", pushed[0].ResourceGroup)
	require.Equal(t, "3.1", *pushed[0].Policy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion)
}

// --- first-time restore creates a policy that doesn't exist yet ---

func TestRestoreAppGWBackupsCreatesPolicyWhenTargetMissing(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID) // intentionally empty: 404 on Get

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	backup := WrappedAppGWPolicy{
		SubscriptionID: azfakesSubID,
		ResourceGroup:  "rg-new",
		Name:           "agw-new",
		Policy:         newAppGWPolicyForTest(),
		PolicyID:       azfakes.AppGWPolicyID(azfakesSubID, "rg-new", "agw-new"),
		WAFType:        WAFTypeAppGW,
	}

	require.NoError(t, restoreAppGWBackups(s, &RestorePoliciesInput{
		BaseCLIInput:  BaseCLIInput{SubscriptionID: azfakesSubID},
		ResourceGroup: "rg-new",
	}, []WrappedAppGWPolicy{backup}))

	pushed := st.PushedAppGW()
	require.Len(t, pushed, 1)
	require.Equal(t, "agw-new", pushed[0].Name)

	_, ok := st.AppGWPolicy("rg-new", "agw-new")
	require.True(t, ok)
}

// --- shouldRestore decision table (non-interactive branches) ---

func TestShouldRestoreDecisions(t *testing.T) {
	fdID := azfakes.FrontDoorPolicyID(azfakesSubID, "rg-one", "fd-one")
	changed := GeneratePolicyPatchOutput{
		CustomRuleChanges: 1, ManagedRuleChanges: 1, TotalRuleDifferences: 2,
	}

	cases := []struct {
		name       string
		found      bool
		matched    WrappedPolicy
		input      RestorePoliciesInput
		patch      GeneratePolicyPatchOutput
		wantOK     bool
		wantErrStr string
	}{
		{
			// regression: AppGW restores never derive a TargetPolicy, so this
			// previously fell through to an interactive Confirm prompt
			name:    "dry run with existing policy and no target proceeds without prompting",
			found:   true,
			matched: WrappedPolicy{PolicyID: fdID},
			input:   RestorePoliciesInput{BaseCLIInput: BaseCLIInput{DryRun: true}},
			patch:   changed,
			wantOK:  true,
		},
		{
			name:   "dry run with target and no existing policy proceeds",
			found:  false,
			input:  RestorePoliciesInput{BaseCLIInput: BaseCLIInput{DryRun: true}, TargetPolicy: fdID},
			wantOK: true,
		},
		{
			name:       "target without existing policy errors",
			found:      false,
			input:      RestorePoliciesInput{TargetPolicy: fdID},
			wantErrStr: "target policy does not exist",
		},
		{
			name:    "identical policies are skipped",
			found:   true,
			matched: WrappedPolicy{PolicyID: fdID},
			input:   RestorePoliciesInput{Force: true},
			patch:   GeneratePolicyPatchOutput{},
			wantOK:  false,
		},
		{
			name:    "custom rules only with no custom changes is skipped",
			found:   true,
			matched: WrappedPolicy{PolicyID: fdID},
			input:   RestorePoliciesInput{CustomRulesOnly: true, Force: true},
			patch:   GeneratePolicyPatchOutput{ManagedRuleChanges: 1, TotalRuleDifferences: 1},
			wantOK:  false,
		},
		{
			name:    "managed rules only with no managed changes is skipped",
			found:   true,
			matched: WrappedPolicy{PolicyID: fdID},
			input:   RestorePoliciesInput{ManagedRulesOnly: true, Force: true},
			patch:   GeneratePolicyPatchOutput{CustomRuleChanges: 1, TotalRuleDifferences: 1},
			wantOK:  false,
		},
		{
			name:       "new policy without resource group errors",
			found:      false,
			input:      RestorePoliciesInput{},
			wantErrStr: "unable to create New Policy",
		},
		{
			name:   "new policy with resource group is allowed",
			found:  false,
			input:  RestorePoliciesInput{ResourceGroup: "rg-one"},
			wantOK: true,
		},
		{
			name:    "force with target and existing policy skips prompt",
			found:   true,
			matched: WrappedPolicy{PolicyID: fdID},
			input:   RestorePoliciesInput{TargetPolicy: fdID, Force: true},
			patch:   changed,
			wantOK:  true,
		},
		{
			name:    "force without target and existing policy skips prompt",
			found:   true,
			matched: WrappedPolicy{PolicyID: fdID},
			input:   RestorePoliciesInput{Force: true},
			patch:   changed,
			wantOK:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := shouldRestore(tc.found, tc.matched, WrappedPolicy{}, &tc.input, tc.patch)

			if tc.wantErrStr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErrStr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantOK, ok)
		})
	}
}

// --- BuildRestoredAppGWPolicy partial restores and non-mutation ---

func appGWPolicyWithCustomRule(ruleName string) armnetwork.WebApplicationFirewallPolicy {
	p := newAppGWPolicyForTest()
	p.Properties.CustomRules = []*armnetwork.WebApplicationFirewallCustomRule{
		{Name: toPtr(ruleName)},
	}

	return p
}

func TestBuildRestoredAppGWPolicyCustomRulesOnly(t *testing.T) {
	existing := &WrappedAppGWPolicy{
		PolicyID: azfakes.AppGWPolicyID(azfakesSubID, "rg-one", "agw-one"),
		Policy:   appGWPolicyWithCustomRule("existing-rule"),
	}

	backupPolicy := appGWPolicyWithCustomRule("backup-rule")
	v31 := "3.1"
	backupPolicy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion = &v31
	backup := &WrappedAppGWPolicy{Name: "agw-one", Policy: backupPolicy}

	got := BuildRestoredAppGWPolicy(existing, backup, &RestorePoliciesInput{CustomRulesOnly: true})

	// custom rules come from the backup; managed rules stay as existing
	require.Len(t, got.Policy.Properties.CustomRules, 1)
	require.Equal(t, "backup-rule", *got.Policy.Properties.CustomRules[0].Name)
	require.Equal(t, "3.2", *got.Policy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion)

	// regression: the caller's existing policy must not be mutated through
	// the shared Properties pointer
	require.Len(t, existing.Policy.Properties.CustomRules, 1)
	require.Equal(t, "existing-rule", *existing.Policy.Properties.CustomRules[0].Name)
}

func TestBuildRestoredAppGWPolicyManagedRulesOnly(t *testing.T) {
	existing := &WrappedAppGWPolicy{
		PolicyID: azfakes.AppGWPolicyID(azfakesSubID, "rg-one", "agw-one"),
		Policy:   appGWPolicyWithCustomRule("existing-rule"),
	}

	backupPolicy := appGWPolicyWithCustomRule("backup-rule")
	v31 := "3.1"
	backupPolicy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion = &v31
	backup := &WrappedAppGWPolicy{Name: "agw-one", Policy: backupPolicy}

	got := BuildRestoredAppGWPolicy(existing, backup, &RestorePoliciesInput{ManagedRulesOnly: true})

	// managed rules come from the backup; custom rules stay as existing
	require.Equal(t, "3.1", *got.Policy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion)
	require.Len(t, got.Policy.Properties.CustomRules, 1)
	require.Equal(t, "existing-rule", *got.Policy.Properties.CustomRules[0].Name)

	// regression: existing must retain its own managed rules
	require.Equal(t, "3.2", *existing.Policy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion)
}
