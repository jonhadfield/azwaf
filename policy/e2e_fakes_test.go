package policy

// End-to-end tests through the exported BackupPolicies and RestorePolicies
// entry points, using the Session injection seam and internal/azfakes. These
// cover the flows that were previously untestable: mixed Front Door + AppGW
// backup and restore, explicit-target restores, dry runs, confirmation
// prompts, and pre-change auto-backups.

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/stretchr/testify/require"

	"github.com/jonhadfield/azwaf/internal/azfakes"
	"github.com/jonhadfield/azwaf/logging"
	"github.com/jonhadfield/azwaf/session"
)

func fdPolicyWithCustomRuleForE2E(ruleName string) armfrontdoor.WebApplicationFirewallPolicy {
	p := fdPolicyForFakeTest()
	p.Properties.CustomRules = &armfrontdoor.CustomRuleList{
		Rules: []*armfrontdoor.CustomRule{{Name: toPtr(ruleName)}},
	}

	return p
}

func wafTypesInDir(t *testing.T, dir string) []string {
	t.Helper()

	files, err := os.ReadDir(dir)
	require.NoError(t, err)

	var types []string

	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		require.NoError(t, err)

		var peek struct{ WAFType string }
		require.NoError(t, json.Unmarshal(data, &peek))
		types = append(types, peek.WAFType)
	}

	return types
}

// --- BackupPolicies end-to-end ---

func TestBackupPoliciesEndToEndMixed(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())
	st.AddAppGWPolicy("rg-one", "agw-one", newAppGWPolicyForTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	dir := t.TempDir()

	require.NoError(t, BackupPolicies(&BackupPoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID, Quiet: true},
		Session:      s,
		Path:         dir,
	}))

	// one file per policy, each tagged with its WAF type
	types := wafTypesInDir(t, dir)
	require.Len(t, types, 2)
	require.Contains(t, types, WAFTypeFrontDoor)
	require.Contains(t, types, WAFTypeAppGW)
}

func TestBackupPoliciesEndToEndFiltersByResourceID(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())
	appgwID := st.AddAppGWPolicy("rg-one", "agw-one", newAppGWPolicyForTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	dir := t.TempDir()

	require.NoError(t, BackupPolicies(&BackupPoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID, Quiet: true},
		Session:      s,
		Path:         dir,
		RIDs:         []string{appgwID},
	}))

	types := wafTypesInDir(t, dir)
	require.Equal(t, []string{WAFTypeAppGW}, types)
}

// --- RestorePolicies end-to-end ---

// writeMixedBackups seeds the store with one FD and one AppGW policy and
// writes backups for both — each differing from the live policy — into a
// single directory, returning it.
func writeMixedBackups(t *testing.T, st *azfakes.Store) string {
	t.Helper()

	fdID := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())
	agwID := st.AddAppGWPolicy("rg-one", "agw-one", newAppGWPolicyForTest())

	dir := t.TempDir()

	fdBackup := WrappedPolicy{
		SubscriptionID: azfakesSubID,
		ResourceGroup:  "rg-one",
		Name:           "fd-one",
		Policy:         fdPolicyWithCustomRuleForE2E("restored-rule"),
		PolicyID:       fdID,
		WAFType:        WAFTypeFrontDoor,
	}
	require.NoError(t, BackupPolicy(&fdBackup, nil, "", true, true, dir))

	agwPolicy := newAppGWPolicyForTest()
	v31 := "3.1"
	agwPolicy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion = &v31
	agwBackup := WrappedAppGWPolicy{
		SubscriptionID: azfakesSubID,
		ResourceGroup:  "rg-one",
		Name:           "agw-one",
		Policy:         agwPolicy,
		PolicyID:       agwID,
		WAFType:        WAFTypeAppGW,
	}
	require.NoError(t, BackupAppGWPolicy(&agwBackup, nil, "", true, true, dir))

	return dir
}

func TestRestorePoliciesMixedBackupsRestoresBothTypes(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	dir := writeMixedBackups(t, st)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	// regression for the TargetPolicy leak: the Front Door branch derives a
	// target from its first backup, and that must not bleed into the AppGW
	// branch — pre-fix this failed with "target policy does not exist"
	require.NoError(t, RestorePolicies(&RestorePoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		Session:      s,
		BackupsPaths: []string{dir},
		Force:        true,
	}))

	fdPushed := st.PushedFrontDoor()
	require.Len(t, fdPushed, 1)
	require.Equal(t, "fd-one", fdPushed[0].Name)
	require.Len(t, fdPushed[0].Policy.Properties.CustomRules.Rules, 1)
	require.Equal(t, "restored-rule", *fdPushed[0].Policy.Properties.CustomRules.Rules[0].Name)

	agwPushed := st.PushedAppGW()
	require.Len(t, agwPushed, 1)
	require.Equal(t, "agw-one", agwPushed[0].Name)
	require.Equal(t, "3.1", *agwPushed[0].Policy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion)
}

func TestRestorePoliciesDryRunPushesNothing(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	dir := writeMixedBackups(t, st)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, RestorePolicies(&RestorePoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID, DryRun: true},
		Session:      s,
		BackupsPaths: []string{dir},
	}))

	require.Empty(t, st.PushedFrontDoor())
	require.Empty(t, st.PushedAppGW())
}

func TestRestorePoliciesExplicitFrontDoorTarget(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	targetID := st.AddFrontDoorPolicy("rg-target", "fd-target", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	// backup originates from a different policy
	dir := t.TempDir()
	backup := WrappedPolicy{
		SubscriptionID: azfakesSubID,
		ResourceGroup:  "rg-src",
		Name:           "fd-src",
		Policy:         fdPolicyWithCustomRuleForE2E("src-rule"),
		PolicyID:       azfakes.FrontDoorPolicyID(azfakesSubID, "rg-src", "fd-src"),
		WAFType:        WAFTypeFrontDoor,
	}
	require.NoError(t, BackupPolicy(&backup, nil, "", true, true, dir))

	require.NoError(t, RestorePolicies(&RestorePoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		Session:      s,
		BackupsPaths: []string{dir},
		TargetPolicy: targetID,
		Force:        true,
	}))

	// the push must land on the explicit target, not the backup's origin
	pushed := st.PushedFrontDoor()
	require.Len(t, pushed, 1)
	require.Equal(t, "fd-target", pushed[0].Name)
	require.Equal(t, "rg-target", pushed[0].ResourceGroup)
	require.Equal(t, "src-rule", *pushed[0].Policy.Properties.CustomRules.Rules[0].Name)
}

// --- confirmation prompts ---

func TestRestorePoliciesPromptDecidesOutcome(t *testing.T) {
	t.Cleanup(func() { confirmInput = os.Stdin })

	t.Run("declined restore pushes nothing", func(t *testing.T) {
		st := azfakes.NewStore(azfakesSubID)
		dir := writeMixedBackups(t, st)

		s, err := st.NewSession(t.TempDir())
		require.NoError(t, err)

		// one answer per prompt: FD then AppGW
		confirmInput = strings.NewReader("n\nn\n")

		require.NoError(t, RestorePolicies(&RestorePoliciesInput{
			BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
			Session:      s,
			BackupsPaths: []string{dir},
		}))

		require.Empty(t, st.PushedFrontDoor())
		require.Empty(t, st.PushedAppGW())
	})

	t.Run("accepted restore pushes both", func(t *testing.T) {
		st := azfakes.NewStore(azfakesSubID)
		dir := writeMixedBackups(t, st)

		s, err := st.NewSession(t.TempDir())
		require.NoError(t, err)

		confirmInput = strings.NewReader("y\ny\n")

		require.NoError(t, RestorePolicies(&RestorePoliciesInput{
			BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
			Session:      s,
			BackupsPaths: []string{dir},
		}))

		require.Len(t, st.PushedFrontDoor(), 1)
		require.Len(t, st.PushedAppGW(), 1)
	})
}

// --- pre-change auto-backup (unblocked by the terminal-width fallback) ---

func TestRestoreAutoBackupWritesPreChangeState(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	dir := writeMixedBackups(t, st)

	baseDir := t.TempDir()
	s, err := st.NewSession(baseDir)
	require.NoError(t, err)

	require.NoError(t, RestorePolicies(&RestorePoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID, AutoBackup: true},
		Session:      s,
		BackupsPaths: []string{dir},
		Force:        true,
	}))

	// both restores pushed
	require.Len(t, st.PushedFrontDoor(), 1)
	require.Len(t, st.PushedAppGW(), 1)

	// pre-change backups of both policies were written to the session's
	// backups dir before pushing
	types := wafTypesInDir(t, s.BackupsDir)
	require.Len(t, types, 2)
	require.Contains(t, types, WAFTypeFrontDoor)
	require.Contains(t, types, WAFTypeAppGW)

	// the AppGW pre-change backup holds the pre-restore ruleset version
	files, err := os.ReadDir(s.BackupsDir)
	require.NoError(t, err)

	for _, f := range files {
		data, rerr := os.ReadFile(filepath.Join(s.BackupsDir, f.Name()))
		require.NoError(t, rerr)

		var peek struct{ WAFType string }
		require.NoError(t, json.Unmarshal(data, &peek))

		if peek.WAFType == WAFTypeAppGW {
			wp, lerr := LoadWrappedAppGWPolicyFromFile(data)
			require.NoError(t, lerr)
			require.Equal(t, "3.2", *wp.Policy.Properties.ManagedRules.ManagedRuleSets[0].RuleSetVersion)
		}
	}
}

// --- DeleteCustomRulesCLI auto-backup ---

// The auto-backup for `delete custom-rule` is pure wiring: the CLI populates
// BaseCLIInput.AutoBackup and DeleteCustomRulesCLI has to forward it as
// ProcessPolicyChangesInput.Backup. It was dropped once already, so assert the
// snapshot lands on disk rather than just that the plumbing type-checks.
func TestDeleteCustomRuleAutoBackupWritesPreChangeState(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyWithCustomRuleForE2E("DropMe"))

	baseDir := t.TempDir()
	s, err := st.NewSession(baseDir)
	require.NoError(t, err)

	require.NoError(t, DeleteCustomRulesCLI(&DeleteCustomRulesCLIInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID, AutoBackup: true},
		Session:      s,
		PolicyID:     rid,
		Name:         "^DropMe$",
	}))

	// the deletion was pushed
	pushed := st.PushedFrontDoor()
	require.Len(t, pushed, 1)
	require.Empty(t, pushed[0].Policy.Properties.CustomRules.Rules)

	// and a pre-change snapshot was written first, still holding the rule
	types := wafTypesInDir(t, s.BackupsDir)
	require.Len(t, types, 1)
	require.Equal(t, WAFTypeFrontDoor, types[0])

	files, err := os.ReadDir(s.BackupsDir)
	require.NoError(t, err)
	require.Len(t, files, 1)

	data, err := os.ReadFile(filepath.Join(s.BackupsDir, files[0].Name()))
	require.NoError(t, err)

	var wp WrappedPolicy
	require.NoError(t, json.Unmarshal(data, &wp))
	require.Len(t, wp.Policy.Properties.CustomRules.Rules, 1)
	require.Equal(t, "DropMe", *wp.Policy.Properties.CustomRules.Rules[0].Name)
}

func TestDeleteCustomRuleWithoutAutoBackupWritesNothing(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyWithCustomRuleForE2E("DropMe"))

	baseDir := t.TempDir()
	s, err := st.NewSession(baseDir)
	require.NoError(t, err)

	require.NoError(t, DeleteCustomRulesCLI(&DeleteCustomRulesCLIInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID, AutoBackup: false},
		Session:      s,
		PolicyID:     rid,
		Name:         "^DropMe$",
	}))

	require.Len(t, st.PushedFrontDoor(), 1)

	files, err := os.ReadDir(s.BackupsDir)
	require.NoError(t, err)
	require.Empty(t, files)
}

// --- DeleteCustomRulesCLI dry-run ---

// DeleteCustomRulesCLIInput used to declare BaseCLIInput as a named field
// alongside duplicate SubscriptionID/DryRun/ConfigPath/Debug fields. The CLI
// populates only BaseCLIInput, so the outer twins were always zero and the
// dry-run guard in ProcessPolicyChanges never fired — --dry-run deleted for
// real. Populate the input exactly as cmd/commands/cmdDelete.go does.
func TestDeleteCustomRuleDryRunPushesNothing(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyWithCustomRuleForE2E("DropMe"))

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, DeleteCustomRulesCLI(&DeleteCustomRulesCLIInput{
		BaseCLIInput: BaseCLIInput{
			SubscriptionID: azfakesSubID,
			DryRun:         true,
			AutoBackup:     true,
		},
		Session:  s,
		PolicyID: rid,
		Name:     "^DropMe$",
	}))

	// nothing pushed, and the rule survives in the store
	require.Empty(t, st.PushedFrontDoor())

	p, ok := st.FrontDoorPolicy("rg-one", "fd-one")
	require.True(t, ok)
	require.Len(t, p.Properties.CustomRules.Rules, 1)
	require.Equal(t, "DropMe", *p.Properties.CustomRules.Rules[0].Name)

	// a dry run must not write an auto-backup either
	files, err := os.ReadDir(s.BackupsDir)
	require.NoError(t, err)
	require.Empty(t, files)
}

// The subscription and config path reached DeleteCustomRulesCLI through the
// same shadowed fields, so a hash or alias resolved against an empty
// subscription. Assert the embedded value is what gets used.
func TestDeleteCustomRuleUsesEmbeddedSubscriptionID(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyWithCustomRuleForE2E("DropMe"))

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	in := &DeleteCustomRulesCLIInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		Session:      s,
		PolicyID:     rid,
		Name:         "^DropMe$",
	}

	// the embedded field is the only SubscriptionID on the struct
	require.Equal(t, azfakesSubID, in.SubscriptionID)
	require.NoError(t, DeleteCustomRulesCLI(in))
	require.Len(t, st.PushedFrontDoor(), 1)
}

// fdPolicyForCopyE2E returns a policy carrying both a named custom rule and a
// managed rule set: copyPolicyRules requires the source to have managed rules
// even when only custom rules are being copied.
func fdPolicyForCopyE2E(ruleName string) armfrontdoor.WebApplicationFirewallPolicy {
	p := fdPolicyWithCustomRuleForE2E(ruleName)
	p.Properties.ManagedRules = &armfrontdoor.ManagedRuleSetList{
		ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
			{
				RuleSetType:    toPtr("Microsoft_DefaultRuleSet"),
				RuleSetVersion: toPtr("2.1"),
			},
		},
	}

	return p
}

// --- CopyRules dry-run (S8) ---

// CopyRulesInput redeclared SubscriptionID/DryRun/Debug/Quiet/AppVersion
// alongside the embedded BaseCLIInput that cmd/commands/cmdCopy.go populates,
// so the outer twins stayed zero and --dry-run pushed to Azure anyway.
// Populate the input exactly as cmdCopy.go does.
func TestCopyRulesDryRunPushesNothing(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	src := st.AddFrontDoorPolicy("rg-one", "fd-src", fdPolicyForCopyE2E("FromSource"))
	tgt := st.AddFrontDoorPolicy("rg-one", "fd-tgt", fdPolicyForCopyE2E("OnTarget"))

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, CopyRules(CopyRulesInput{
		BaseCLIInput: BaseCLIInput{
			SubscriptionID: azfakesSubID,
			AppVersion:     "test-version",
			DryRun:         true,
			AutoBackup:     true,
		},
		Session:         s,
		Source:          src,
		Target:          tgt,
		CustomRulesOnly: true,
	}))

	// nothing pushed, and the target keeps its own rule
	require.Empty(t, st.PushedFrontDoor())

	p, ok := st.FrontDoorPolicy("rg-one", "fd-tgt")
	require.True(t, ok)
	require.Len(t, p.Properties.CustomRules.Rules, 1)
	require.Equal(t, "OnTarget", *p.Properties.CustomRules.Rules[0].Name)

	// a dry run must not write an auto-backup either
	files, err := os.ReadDir(s.BackupsDir)
	require.NoError(t, err)
	require.Empty(t, files)
}

// Without --dry-run the copy lands, and the embedded SubscriptionID and
// AppVersion are the ones actually used.
func TestCopyRulesAppliesAndUsesEmbeddedFields(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	src := st.AddFrontDoorPolicy("rg-one", "fd-src", fdPolicyForCopyE2E("FromSource"))
	tgt := st.AddFrontDoorPolicy("rg-one", "fd-tgt", fdPolicyForCopyE2E("OnTarget"))

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	in := CopyRulesInput{
		BaseCLIInput: BaseCLIInput{
			SubscriptionID: azfakesSubID,
			AppVersion:     "test-version",
			AutoBackup:     true,
		},
		Session:         s,
		Source:          src,
		Target:          tgt,
		CustomRulesOnly: true,
	}

	// the embedded fields are the only ones on the struct
	require.Equal(t, azfakesSubID, in.SubscriptionID)
	require.Equal(t, "test-version", in.AppVersion)

	require.NoError(t, CopyRules(in))

	pushed := st.PushedFrontDoor()
	require.Len(t, pushed, 1)
	require.Len(t, pushed[0].Policy.Properties.CustomRules.Rules, 1)
	require.Equal(t, "FromSource", *pushed[0].Policy.Properties.CustomRules.Rules[0].Name)

	// the pre-change auto-backup captured the target as it was
	files, err := os.ReadDir(s.BackupsDir)
	require.NoError(t, err)
	require.Len(t, files, 1)

	data, err := os.ReadFile(filepath.Join(s.BackupsDir, files[0].Name()))
	require.NoError(t, err)

	var wp WrappedPolicy
	require.NoError(t, json.Unmarshal(data, &wp))
	require.Equal(t, "OnTarget", *wp.Policy.Properties.CustomRules.Rules[0].Name)
}

// --- Alias resolution on the delete commands (S4) ---

// writeAliasConfig writes a config file mapping alias -> full resource id and
// returns its path.
func writeAliasConfig(t *testing.T, alias, resourceID string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "policy_aliases:\n  " + alias + ": " + resourceID + "\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	return path
}

// fdPolicyWithRuleSetExclusionForE2E returns a policy carrying one rule-set
// scoped exclusion, so a delete has something to remove.
func fdPolicyWithRuleSetExclusionForE2E() armfrontdoor.WebApplicationFirewallPolicy {
	mv := armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames
	mo := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEquals

	p := fdPolicyForFakeTest()
	p.Properties.ManagedRules = &armfrontdoor.ManagedRuleSetList{
		ManagedRuleSets: []*armfrontdoor.ManagedRuleSet{
			{
				RuleSetType:    toPtr("Microsoft_DefaultRuleSet"),
				RuleSetVersion: toPtr("2.1"),
				Exclusions: []*armfrontdoor.ManagedRuleExclusion{
					{
						MatchVariable:         &mv,
						Selector:              toPtr("User-Agent"),
						SelectorMatchOperator: &mo,
					},
				},
			},
		},
	}

	return p
}

// An alias contains no "/", so the pre-resolution ValidateResourceID check the
// delete commands used to run rejected it outright.
func TestDeleteCustomRuleResolvesAlias(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyWithCustomRuleForE2E("DropMe"))

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, DeleteCustomRulesCLI(&DeleteCustomRulesCLIInput{
		BaseCLIInput: BaseCLIInput{
			SubscriptionID: azfakesSubID,
			ConfigPath:     writeAliasConfig(t, "prod-waf", rid),
		},
		Session:  s,
		PolicyID: "prod-waf",
		Name:     "^DropMe$",
	}))

	pushed := st.PushedFrontDoor()
	require.Len(t, pushed, 1)
	require.Equal(t, "fd-one", pushed[0].Name)
	require.Empty(t, pushed[0].Policy.Properties.CustomRules.Rules)
}

func TestDeleteManagedRuleExclusionResolvesAlias(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyWithRuleSetExclusionForE2E())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, DeleteManagedRuleExclusion(&DeleteManagedRuleExclusionCLIInput{
		BaseCLIInput: BaseCLIInput{
			SubscriptionID: azfakesSubID,
			ConfigPath:     writeAliasConfig(t, "prod-waf", rid),
		},
		Session:               s,
		PolicyID:              "prod-waf",
		RuleSet:               "Microsoft_DefaultRuleSet_2.1",
		ExclusionRuleVariable: "RequestHeaderNames",
		ExclusionRuleOperator: "Equals",
		ExclusionRuleSelector: "User-Agent",
	}))

	pushed := st.PushedFrontDoor()
	require.Len(t, pushed, 1)
	require.Equal(t, "fd-one", pushed[0].Name)
	require.Empty(t, pushed[0].Policy.Properties.ManagedRules.ManagedRuleSets[0].Exclusions)
}

// An unresolvable name must surface the resolver's error rather than being
// swallowed: delete custom-rule used to return ShowSubcommandHelp's nil error.
func TestDeleteCommandsRejectUnknownPolicyName(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	err = DeleteCustomRulesCLI(&DeleteCustomRulesCLIInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		Session:      s,
		PolicyID:     "no-such-alias",
		Name:         "^DropMe$",
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to find provided policy")

	err = DeleteManagedRuleExclusion(&DeleteManagedRuleExclusionCLIInput{
		BaseCLIInput:          BaseCLIInput{SubscriptionID: azfakesSubID},
		Session:               s,
		PolicyID:              "no-such-alias",
		RuleSet:               "Microsoft_DefaultRuleSet_2.1",
		ExclusionRuleVariable: "RequestHeaderNames",
		ExclusionRuleOperator: "Equals",
		ExclusionRuleSelector: "User-Agent",
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to find provided policy")

	require.Empty(t, st.PushedFrontDoor())
}

// failingContainerURL returns a container url served by a local test server.
// Uploads to it fail immediately — the Azure credential refuses to send a
// bearer token over plaintext http — which is all these tests need, and keeps
// them off the network and free of SDK retry backoff. The /account/container
// path shape is what azblob.ParseURL expects of an IP-style endpoint.
func failingContainerURL(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	return srv.URL + "/myacct/waf-backups"
}

// --- Backup destination wiring (S2) ---

// A container url used to be rejected unless a storage account resource id was
// supplied alongside it, even though the README documents the two as
// alternatives. It now stands alone, authenticating with the session's Azure AD
// credential.
func TestNewBackupBlobClientAcceptsContainerURLAlone(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	client, container, err := newBackupBlobClient(s, "", "https://myacc.blob.core.windows.net/waf-backups")
	require.NoError(t, err)
	require.NotNil(t, client)
	require.Equal(t, "waf-backups", container)
	require.Equal(t, "https://myacc.blob.core.windows.net/", client.URL())
}

// No storage destination at all is not an error: the backup goes to local disk.
func TestNewBackupBlobClientWithoutDestination(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	client, container, err := newBackupBlobClient(s, "", "")
	require.NoError(t, err)
	require.Nil(t, client)
	require.Empty(t, container)
}

// A storage account on its own still cannot work: nothing names the container.
func TestNewBackupBlobClientRejectsStorageAccountWithoutContainer(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	_, _, err = newBackupBlobClient(s,
		"/subscriptions/"+azfakesSubID+"/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/myacc", "")
	require.ErrorContains(t, err, "container url is required")
}

func TestNewBackupBlobClientRejectsMalformedContainerURL(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	// a service url naming no container
	_, _, err = newBackupBlobClient(s, "", "https://myacc.blob.core.windows.net/")
	require.ErrorContains(t, err, "does not name a container")
}

// BackupPolicies must accept a container url as the sole destination, where it
// previously failed the "both are required" check before fetching anything.
func TestBackupPoliciesAcceptsContainerURLAsOnlyDestination(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	// FailFast surfaces what happened rather than swallowing it. The upload to
	// a non-existent account is expected to fail; what matters is that the run
	// reached the upload at all, instead of being rejected up front by the
	// destination check.
	err = BackupPolicies(&BackupPoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		Session:      s,
		ContainerURL: failingContainerURL(t),
		FailFast:     true,
	})

	require.Error(t, err)
	require.NotContains(t, err.Error(), "either path or storage account details are required")
	require.NotContains(t, err.Error(), "both storage account resource id and container url are required")
}

// With neither a path nor a container url there is nowhere to write.
func TestBackupPoliciesRequiresADestination(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	err = BackupPolicies(&BackupPoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		Session:      s,
	})
	require.ErrorContains(t, err, "either path or storage account details are required")
}

// --- Local backup survives a failed upload (S17) ---

// The blob upload used to run before the local write and return its error
// unconditionally, ignoring failFast. A single unreachable container therefore
// discarded the local copy too, and backupPolicies swallowed the error, so the
// command exited 0 having written nothing at all.
func TestBackupPoliciesWritesLocallyWhenUploadFails(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())
	st.AddAppGWPolicy("rg-one", "agw-one", newAppGWPolicyForTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	dir := t.TempDir()

	// the container does not exist, so every upload fails
	require.NoError(t, BackupPolicies(&BackupPoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		Session:      s,
		ContainerURL: failingContainerURL(t),
		Path:         dir,
	}))

	// both policies still reached disk
	types := wafTypesInDir(t, dir)
	require.Len(t, types, 2)
	require.Contains(t, types, WAFTypeFrontDoor)
	require.Contains(t, types, WAFTypeAppGW)
}

// With FailFast the upload error must surface rather than being logged away,
// but the local copy is written first regardless.
func TestBackupPoliciesFailFastSurfacesUploadErrorAfterLocalWrite(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	dir := t.TempDir()

	err = BackupPolicies(&BackupPoliciesInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		Session:      s,
		ContainerURL: failingContainerURL(t),
		Path:         dir,
		FailFast:     true,
	})
	require.ErrorContains(t, err, "failed to upload")

	files, rerr := os.ReadDir(dir)
	require.NoError(t, rerr)
	require.Len(t, files, 1)
}

// --- copy --async (S1) ---

// captureLogs redirects the library logger into a buffer at info level.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	t.Cleanup(func() {
		logging.SetLevel(slog.LevelWarn)
		logging.SetOutput(os.Stderr)
	})

	var buf bytes.Buffer

	logging.SetOutput(&buf)
	logging.SetLevel(slog.LevelInfo)

	return &buf
}

func copyRulesInputForAsyncTest(st *azfakes.Store, s *session.Session, async bool) CopyRulesInput {
	src := st.AddFrontDoorPolicy("rg-one", "fd-src", fdPolicyForCopyE2E("FromSource"))
	tgt := st.AddFrontDoorPolicy("rg-one", "fd-tgt", fdPolicyForCopyE2E("OnTarget"))

	return CopyRulesInput{
		BaseCLIInput:    BaseCLIInput{SubscriptionID: azfakesSubID, AppVersion: "test-version"},
		Session:         s,
		Source:          src,
		Target:          tgt,
		CustomRulesOnly: true,
		Async:           async,
	}
}

// --async was parsed by the CLI and then dropped: CopyRules never passed it to
// ProcessPolicyChanges, so PushPolicyInput.Async stayed false and the push
// always waited. The two paths are distinguishable by what they log.
func TestCopyRulesAsyncDoesNotWaitForCompletion(t *testing.T) {
	buf := captureLogs(t)

	st := azfakes.NewStore(azfakesSubID)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, CopyRules(copyRulesInputForAsyncTest(st, s, true)))

	require.Len(t, st.PushedFrontDoor(), 1)
	require.Contains(t, buf.String(), "asynchronous policy push started")
	require.NotContains(t, buf.String(), "policy fd-tgt updated")
}

// Without --async the push is awaited, as before.
func TestCopyRulesWithoutAsyncWaitsForCompletion(t *testing.T) {
	buf := captureLogs(t)

	st := azfakes.NewStore(azfakesSubID)

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, CopyRules(copyRulesInputForAsyncTest(st, s, false)))

	require.Len(t, st.PushedFrontDoor(), 1)
	require.Contains(t, buf.String(), "policy fd-tgt updated")
	require.NotContains(t, buf.String(), "asynchronous policy push started")
}

// Commands with no --async flag must keep waiting for the push.
func TestDeleteCustomRuleIsNotAsync(t *testing.T) {
	buf := captureLogs(t)

	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyWithCustomRuleForE2E("DropMe"))

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, DeleteCustomRulesCLI(&DeleteCustomRulesCLIInput{
		BaseCLIInput: BaseCLIInput{SubscriptionID: azfakesSubID},
		Session:      s,
		PolicyID:     rid,
		Name:         "^DropMe$",
	}))

	require.Contains(t, buf.String(), "policy fd-one updated")
	require.NotContains(t, buf.String(), "asynchronous policy push started")
}

// fdPolicySourceForCopy / fdPolicyTargetForCopy differ in *both* their custom
// rules and their managed-rule exclusions, while keeping the same rule set type
// and version. Without a real difference CopyRules returns early ("rules are
// already identical") and never reaches copyPolicyRules.
func fdPolicySourceForCopy() armfrontdoor.WebApplicationFirewallPolicy {
	mv := armfrontdoor.ManagedRuleExclusionMatchVariableRequestHeaderNames
	mo := armfrontdoor.ManagedRuleExclusionSelectorMatchOperatorEquals

	p := fdPolicyForCopyE2E("FromSource")
	p.Properties.ManagedRules.ManagedRuleSets[0].Exclusions = []*armfrontdoor.ManagedRuleExclusion{
		{MatchVariable: &mv, Selector: toPtr("User-Agent"), SelectorMatchOperator: &mo},
	}

	return p
}

func fdPolicyTargetForCopy() armfrontdoor.WebApplicationFirewallPolicy {
	return fdPolicyForCopyE2E("OnTarget")
}

// --- copy writes no debug noise to stdout (A4 / S12) ---

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout

	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	done := make(chan string, 1)

	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	require.NoError(t, w.Close())

	os.Stdout = orig

	return <-done
}

// copyPolicyRules used to dump four %#+v renderings of the policy internals to
// stdout on every managed-rule copy, corrupting anything piping the output.
// That detail belongs at debug level on the library's own logger.
func TestCopyRulesWritesNothingToStdout(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		customRulesOnly, managedRules bool
	}{
		{"managed rules only", false, true},
		{"custom rules only", true, false},
		{"both", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureLogs(t)

			st := azfakes.NewStore(azfakesSubID)
			src := st.AddFrontDoorPolicy("rg-one", "fd-src", fdPolicySourceForCopy())
			tgt := st.AddFrontDoorPolicy("rg-one", "fd-tgt", fdPolicyTargetForCopy())

			s, err := st.NewSession(t.TempDir())
			require.NoError(t, err)

			var copyErr error

			stdout := captureStdout(t, func() {
				copyErr = CopyRules(CopyRulesInput{
					BaseCLIInput:     BaseCLIInput{SubscriptionID: azfakesSubID, AppVersion: "test-version"},
					Session:          s,
					Source:           src,
					Target:           tgt,
					CustomRulesOnly:  tc.customRulesOnly,
					ManagedRulesOnly: tc.managedRules,
				})
			})

			require.NoError(t, copyErr)

			// the copy really ran, rather than short-circuiting on identical rules
			require.Len(t, st.PushedFrontDoor(), 1)
			require.Empty(t, stdout, "copy must not write to stdout, got: %s", stdout)

			// info level carries the push confirmation but none of the dumps
			require.NotContains(t, buf.String(), "%#+v")
			require.NotContains(t, buf.String(), "copying")
		})
	}
}

// The detail the prints carried is still available, just at debug level.
func TestCopyRulesLogsDetailAtDebugLevel(t *testing.T) {
	t.Cleanup(func() {
		logging.SetLevel(slog.LevelWarn)
		logging.SetOutput(os.Stderr)
	})

	var buf bytes.Buffer

	logging.SetOutput(&buf)
	logging.SetLevel(slog.LevelDebug)

	st := azfakes.NewStore(azfakesSubID)
	src := st.AddFrontDoorPolicy("rg-one", "fd-src", fdPolicySourceForCopy())
	tgt := st.AddFrontDoorPolicy("rg-one", "fd-tgt", fdPolicyTargetForCopy())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, CopyRules(CopyRulesInput{
		BaseCLIInput:     BaseCLIInput{SubscriptionID: azfakesSubID, AppVersion: "test-version"},
		Session:          s,
		Source:           src,
		Target:           tgt,
		ManagedRulesOnly: true,
	}))

	require.Contains(t, buf.String(), "copying managed rules only")
}

// --- get custom-rule --output (S3) ---

// The --output flag was declared on the CLI and never read: the rule always
// went to stdout, so `azwaf get custom-rule ... --output rule.json` wrote no
// file and silently printed instead.
func TestPrintPolicyCustomRuleWritesToOutputPath(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyWithCustomRuleForE2E("BlockBadActor"))

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "rule.json")

	stdout := captureStdout(t, func() {
		err = PrintPolicyCustomRule(PrintPolicyCustomRuleInput{
			Session:        s,
			SubscriptionID: azfakesSubID,
			ExtendedID:     rid + "|BlockBadActor",
			OutputPath:     path,
			Quiet:          true,
		})
	})
	require.NoError(t, err)

	// the rule landed in the file, not on stdout
	require.Empty(t, stdout)

	data, rerr := os.ReadFile(path)
	require.NoError(t, rerr)

	var rule armfrontdoor.CustomRule
	require.NoError(t, json.Unmarshal(data, &rule))
	require.Equal(t, "BlockBadActor", *rule.Name)
}

// Without --output the rule still goes to stdout, so piping into jq keeps working.
func TestPrintPolicyCustomRuleWithoutOutputPathPrints(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyWithCustomRuleForE2E("BlockBadActor"))

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	stdout := captureStdout(t, func() {
		err = PrintPolicyCustomRule(PrintPolicyCustomRuleInput{
			Session:        s,
			SubscriptionID: azfakesSubID,
			ExtendedID:     rid + "|BlockBadActor",
		})
	})
	require.NoError(t, err)

	var rule armfrontdoor.CustomRule
	require.NoError(t, json.Unmarshal([]byte(stdout), &rule))
	require.Equal(t, "BlockBadActor", *rule.Name)
}

// An unwritable output path must be reported, not swallowed.
func TestPrintPolicyCustomRuleReportsUnwritableOutputPath(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyWithCustomRuleForE2E("BlockBadActor"))

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	err = PrintPolicyCustomRule(PrintPolicyCustomRuleInput{
		Session:        s,
		SubscriptionID: azfakesSubID,
		ExtendedID:     rid + "|BlockBadActor",
		OutputPath:     filepath.Join(t.TempDir(), "no-such-dir", "rule.json"),
	})
	require.ErrorContains(t, err, "failed to write custom rule")
}

// --output also resolves the policy by alias, like every other command.
func TestPrintPolicyCustomRuleResolvesAlias(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	rid := st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyWithCustomRuleForE2E("BlockBadActor"))

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "rule.json")

	require.NoError(t, PrintPolicyCustomRule(PrintPolicyCustomRuleInput{
		Session:        s,
		SubscriptionID: azfakesSubID,
		ExtendedID:     "prod-waf|BlockBadActor",
		ConfigPath:     writeAliasConfig(t, "prod-waf", rid),
		OutputPath:     path,
		Quiet:          true,
	}))

	_, serr := os.Stat(path)
	require.NoError(t, serr)
}

// --- the 90-custom-rule limit is enforced before pushing (S10) ---

// fdPolicyWithNCustomRules returns a policy carrying n custom rules.
func fdPolicyWithNCustomRules(n int) armfrontdoor.WebApplicationFirewallPolicy {
	p := fdPolicyForCopyE2E("Filler")

	rules := make([]*armfrontdoor.CustomRule, 0, n)
	for i := range n {
		rules = append(rules, &armfrontdoor.CustomRule{
			Name:     toPtr("Rule" + strconv.Itoa(i)),
			Priority: toPtr(int32(i + 1)),
		})
	}

	p.Properties.CustomRules = &armfrontdoor.CustomRuleList{Rules: rules}
	// PushPolicy logs *Policy.Name, which the fake store only fills in on upsert
	p.Name = toPtr("fd-one")

	return p
}

// copy and restore replace CustomRules wholesale. Neither counted them, so
// either could push a policy Azure would reject — after paying for a fetch, a
// diff and an auto-backup.
func TestCopyRulesRejectsOverLimitCustomRules(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	src := st.AddFrontDoorPolicy("rg-one", "fd-src", fdPolicyWithNCustomRules(MaxCustomRules+1))
	tgt := st.AddFrontDoorPolicy("rg-one", "fd-tgt", fdPolicyForCopyE2E("OnTarget"))

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	err = CopyRules(CopyRulesInput{
		BaseCLIInput:    BaseCLIInput{SubscriptionID: azfakesSubID, AutoBackup: true},
		Session:         s,
		Source:          src,
		Target:          tgt,
		CustomRulesOnly: true,
	})

	require.ErrorContains(t, err, "exceeding Azure's limit of 90")
	require.Empty(t, st.PushedFrontDoor())

	// and it failed early enough that no auto-backup was written
	files, rerr := os.ReadDir(s.BackupsDir)
	require.NoError(t, rerr)
	require.Empty(t, files)
}

// A dry run must report the problem rather than reporting success, so the check
// has to run before the dry-run return.
func TestProcessPolicyChangesDryRunStillReportsOverLimit(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	err = ProcessPolicyChanges(&ProcessPolicyChangesInput{
		Session:          s,
		PolicyName:       "fd-one",
		SubscriptionID:   azfakesSubID,
		ResourceGroup:    "rg-one",
		PolicyPostChange: fdPolicyWithNCustomRules(MaxCustomRules + 1),
		DryRun:           true,
	})

	require.ErrorContains(t, err, "exceeding Azure's limit of 90")
	require.Empty(t, st.PushedFrontDoor())
}

// Exactly at the limit is allowed: the check must not be off by one.
func TestProcessPolicyChangesAllowsExactlyTheLimit(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, ProcessPolicyChanges(&ProcessPolicyChangesInput{
		Session:          s,
		PolicyName:       "fd-one",
		SubscriptionID:   azfakesSubID,
		ResourceGroup:    "rg-one",
		PolicyPostChange: fdPolicyWithNCustomRules(MaxCustomRules),
	}))

	require.Len(t, st.PushedFrontDoor(), 1)
}

// PushPolicy is the backstop for callers that bypass ProcessPolicyChanges.
func TestPushPolicyRejectsOverLimitCustomRules(t *testing.T) {
	st := azfakes.NewStore(azfakesSubID)
	st.AddFrontDoorPolicy("rg-one", "fd-one", fdPolicyForFakeTest())

	s, err := st.NewSession(t.TempDir())
	require.NoError(t, err)

	err = PushPolicy(s, &PushPolicyInput{
		Name:          "fd-one",
		Subscription:  azfakesSubID,
		ResourceGroup: "rg-one",
		Policy:        fdPolicyWithNCustomRules(MaxCustomRules + 1),
	})

	require.ErrorContains(t, err, "exceeding Azure's limit of 90")
	require.Empty(t, st.PushedFrontDoor())
}

// A policy with no custom rules at all must not trip the check.
func TestValidatePolicyLimitsToleratesEmptyPolicy(t *testing.T) {
	require.NoError(t, validatePolicyLimits(nil))
	require.NoError(t, validatePolicyLimits(&armfrontdoor.WebApplicationFirewallPolicy{}))

	p := fdPolicyForFakeTest()
	require.NoError(t, validatePolicyLimits(&p))
}
