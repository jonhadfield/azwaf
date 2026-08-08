package policy

// End-to-end tests through the exported BackupPolicies and RestorePolicies
// entry points, using the Session injection seam and internal/azfakes. These
// cover the flows that were previously untestable: mixed Front Door + AppGW
// backup and restore, explicit-target restores, dry runs, confirmation
// prompts, and pre-change auto-backups.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor"
	"github.com/jonhadfield/azwaf/internal/azfakes"
	"github.com/stretchr/testify/require"
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
